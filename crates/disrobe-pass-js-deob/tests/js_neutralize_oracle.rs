#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use disrobe_core::neutralize::{
    Applied, NeutralizationPlan, NeutralizeError, RuntimeCheck, Selection, apply,
};
use disrobe_core::scratch::ScratchDir;
use disrobe_pass_js_deob::protectors::neutralize::{
    JsNeutralizeError, MAX_SCAN_BYTES, MAX_SITES, plan_js_neutralization,
};
use disrobe_pass_js_deob::{ObfuscatorIoOptions, ObfuscatorIoOutput, obfuscator_io_deobfuscate};

#[path = "common/mod.rs"]
mod common;

const NODE_TIMEOUT: Duration = Duration::from_mins(1);

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(rel)
}

fn fixture(name: &str) -> PathBuf {
    repo_path("corpus/js/anti-analysis").join(name)
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("required fixture {}: {error}", path.display()))
}

struct NodeRun {
    status: Option<i32>,
    stdout: String,
}

fn run_node(args: &[&Path], argv: &[&str]) -> NodeRun {
    let mut command: Command = Command::new("node");
    command
        .env_remove("FORCE_COLOR")
        .env("NO_COLOR", "1")
        .args(args)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child: std::process::Child = command
        .spawn()
        .unwrap_or_else(|error| panic!("node is required for the neutralization grade: {error}"));
    let started: Instant = Instant::now();
    loop {
        if child.try_wait().expect("poll node").is_some() {
            break;
        }
        if started.elapsed() > NODE_TIMEOUT {
            child.kill().expect("stop node after the timeout");
            panic!("node exceeded {NODE_TIMEOUT:?} on {args:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output: std::process::Output = child.wait_with_output().expect("collect node output");
    NodeRun {
        status: output.status.code(),
        stdout: String::from_utf8(output.stdout).expect("node stdout is UTF-8"),
    }
}

fn plan_for(source: &str) -> NeutralizationPlan {
    plan_js_neutralization(source).unwrap_or_else(|error| panic!("plan: {error}"))
}

fn applied(source: &str, plan: &NeutralizationPlan) -> String {
    let out: Applied = apply(source.as_bytes(), plan, &Selection::All).expect("apply the plan");
    assert_eq!(out.report.applied.len(), plan.patches.len());
    assert_eq!(
        out.bytes.len(),
        source.len(),
        "patches never change the length"
    );
    String::from_utf8(out.bytes).expect("patched script stays UTF-8")
}

fn write_copy(dir: &ScratchDir, name: &str, text: &str) -> PathBuf {
    let path: PathBuf = dir.path().join(name);
    fs::write(&path, text).expect("write the neutralized copy");
    path
}

fn assert_wrong_original_bytes_are_refused(source: &str, plan: &NeutralizationPlan) {
    let mut mutated: NeutralizationPlan = plan.clone();
    let first: &mut disrobe_core::neutralize::Patch =
        mutated.patches.first_mut().expect("the plan holds a patch");
    first.original[0] ^= 0x20;
    let err: NeutralizeError = apply(source.as_bytes(), &mutated, &Selection::All)
        .expect_err("a patch whose original bytes differ must be refused");
    assert!(
        matches!(err, NeutralizeError::OriginalMismatch { .. }),
        "{err:?}"
    );
    let skipped: Applied =
        apply(source.as_bytes(), plan, &Selection::Skip).expect("skip leaves the input alone");
    assert_eq!(skipped.bytes, source.as_bytes());
    assert!(skipped.report.applied.is_empty());
}

fn checks(plan: &NeutralizationPlan) -> BTreeSet<RuntimeCheck> {
    plan.checks()
}

struct LockCase {
    file: &'static str,
    locked_stdout: &'static str,
    unlocked_stdout: &'static str,
    checks: &'static [RuntimeCheck],
    patches: usize,
}

const LOCK_CASES: [LockCase; 5] = [
    LockCase {
        file: "domain_lock.obfuscator-io.js",
        locked_stdout: "locked: navigation to about:blank\n",
        unlocked_stdout: "unlocked: checksum 1671826638\n",
        checks: &[RuntimeCheck::JsDomainLock],
        patches: 1,
    },
    LockCase {
        file: "domain_lock.jsconfuser.js",
        locked_stdout: "locked: domain lock countermeasure\n",
        unlocked_stdout: "unlocked: fib(30) = 832040\n",
        checks: &[RuntimeCheck::JsDomainLock],
        patches: 1,
    },
    LockCase {
        file: "date_lock.jsconfuser.js",
        locked_stdout: "locked: date lock countermeasure\n",
        unlocked_stdout: "unlocked: a|1;b|2\n",
        checks: &[RuntimeCheck::JsDateLock],
        patches: 2,
    },
    LockCase {
        file: "host_probe.js",
        locked_stdout: "locked: not a browser host\n",
        unlocked_stdout: "unlocked: 0:ALPHA,1:BETA,2:GAMMA\n",
        checks: &[RuntimeCheck::JsHostEnvironmentProbe],
        patches: 3,
    },
    LockCase {
        file: "console_hijack.obfuscator-io.js",
        locked_stdout: "",
        unlocked_stdout: "unlocked: words 5\n",
        checks: &[RuntimeCheck::JsConsoleHijack],
        patches: 1,
    },
];

#[test]
fn authored_locks_print_the_unlocked_branch_only_after_the_plan_is_applied() {
    let scratch: ScratchDir = ScratchDir::create("disrobe-js-neutralize-locks").expect("scratch");
    for case in &LOCK_CASES {
        let path: PathBuf = fixture(case.file);
        let source: String = read(&path);
        let original: NodeRun = run_node(&[&path], &[]);
        assert_eq!(
            original.stdout, case.locked_stdout,
            "{}: the authored original must take its locked branch under node",
            case.file
        );

        let plan: NeutralizationPlan = plan_for(&source);
        assert_eq!(
            checks(&plan),
            case.checks
                .iter()
                .copied()
                .collect::<BTreeSet<RuntimeCheck>>(),
            "{}: {plan:#?}",
            case.file
        );
        assert_eq!(plan.patches.len(), case.patches, "{}: {plan:#?}", case.file);
        assert!(plan.refusals.is_empty(), "{}: {plan:#?}", case.file);
        for patch in &plan.patches {
            assert!(!patch.anchor.pattern.is_empty() && !patch.anchor.instruction.is_empty());
            assert!(!patch.risk.is_empty());
            assert_eq!(patch.anchor.address, patch.file_offset);
        }

        let patched: String = applied(&source, &plan);
        let copy: PathBuf = write_copy(&scratch, case.file, &patched);
        let unlocked: NodeRun = run_node(&[&copy], &[]);
        assert_eq!(unlocked.status, Some(0), "{}", case.file);
        assert_eq!(
            unlocked.stdout, case.unlocked_stdout,
            "{}: the plan-applied copy must print the unlocked branch\n{patched}",
            case.file
        );
        assert!(
            plan_for(&patched).patches.is_empty(),
            "{}: the applied copy still plans patches",
            case.file
        );
        assert_wrong_original_bytes_are_refused(&source, &plan);
    }
}

struct TrapCase {
    file: &'static str,
    stdout: &'static str,
    pauses_before: &'static str,
    patches: usize,
}

const TRAP_CASES: [TrapCase; 2] = [
    TrapCase {
        file: "anti_debug.jsconfuser.js",
        stdout: "unlocked: digest 585272\n",
        pauses_before: "debugger pauses: 8\n",
        patches: 2,
    },
    TrapCase {
        file: "debug_protection.obfuscator-io.js",
        stdout: "unlocked: 7,14,21\n",
        pauses_before: "debugger pauses: 64 (limit reached)\n",
        patches: 3,
    },
];

#[test]
fn debugger_traps_stop_pausing_an_attached_inspector_after_the_plan() {
    let scratch: ScratchDir = ScratchDir::create("disrobe-js-neutralize-traps").expect("scratch");
    let harness: PathBuf = fixture("debugger_harness.js");
    for case in &TRAP_CASES {
        let path: PathBuf = fixture(case.file);
        let source: String = read(&path);
        let before: NodeRun = run_node(&[&harness, &path], &[]);
        assert_eq!(
            before.stdout,
            format!("{}{}", case.stdout, case.pauses_before),
            "{}: the original must pause the attached inspector",
            case.file
        );

        let plan: NeutralizationPlan = plan_for(&source);
        assert_eq!(
            checks(&plan),
            BTreeSet::from([RuntimeCheck::JsDebuggerTrap]),
            "{}: {plan:#?}",
            case.file
        );
        assert_eq!(plan.patches.len(), case.patches, "{}: {plan:#?}", case.file);
        let patched: String = applied(&source, &plan);
        let copy: PathBuf = write_copy(&scratch, case.file, &patched);
        let after: NodeRun = run_node(&[&harness, &copy], &[]);
        assert_eq!(
            after.stdout,
            format!("{}debugger pauses: 0\n", case.stdout),
            "{}: the plan-applied copy must run unpaused with the same output\n{patched}",
            case.file
        );
        assert_wrong_original_bytes_are_refused(&source, &plan);
    }
}

#[test]
fn clean_programs_get_an_empty_plan() {
    let harness: PathBuf = fixture("debugger_harness.js");
    let clean: PathBuf = fixture("clean.js");
    let run: NodeRun = run_node(&[&harness, &clean], &[]);
    assert!(
        run.stdout.ends_with("debugger pauses: 0\n"),
        "{}",
        run.stdout
    );
    for path in [
        clean,
        repo_path("corpus/src/javascript/obfuscator-io-high.js"),
        repo_path("corpus/js/hello.js"),
        repo_path("corpus/js/jsconfuser/recovery/src_integrity.js"),
        repo_path("corpus/js/jsobfu/input.js"),
    ] {
        let plan: NeutralizationPlan = plan_for(&read(&path));
        assert!(
            plan.patches.is_empty() && plan.refusals.is_empty(),
            "{}: {plan:#?}",
            path.display()
        );
    }
}

fn boa(program: &str, argv: &[&str]) -> common::EvalOutcome {
    let executable: PathBuf = std::env::current_exe().expect("test executable");
    common::BoaWorker::new(executable)
        .expect("Boa worker")
        .evaluate(program, argv)
        .expect("Boa worker evaluation")
}

fn boa_stdout(outcome: &common::EvalOutcome) -> Option<String> {
    let common::Terminal::Completed(_) = &outcome.terminal else {
        return None;
    };
    let mut out: String = String::new();
    for event in &outcome.trace {
        if event.call == "console.log" {
            let values: Vec<String> = event
                .arguments
                .iter()
                .map(|value| value.value.clone())
                .collect();
            out.push_str(&values.join(" "));
            out.push('\n');
        }
    }
    Some(out)
}

#[test]
fn real_obfuscator_io_console_hijack_plan_restores_console_output() {
    let clean: NodeRun = run_node(
        &[&repo_path("corpus/src/javascript/obfuscator-io-high.js")],
        &[],
    );
    assert!(
        clean.stdout.contains("calculator ready"),
        "{}",
        clean.stdout
    );
    let source: String = read(&repo_path(
        "corpus/src/javascript/obfuscator-io-samples/presets/low.js",
    ));
    let silenced: String = boa_stdout(&boa(&source, &[])).expect("the hijacked original completes");
    let first_line: &str = clean
        .stdout
        .split_inclusive('\n')
        .next()
        .unwrap_or_default();
    assert_eq!(
        silenced, first_line,
        "the real low preset silences console after the first call captured console.log"
    );
    let plan: NeutralizationPlan = plan_for(&source);
    assert_eq!(
        checks(&plan),
        BTreeSet::from([RuntimeCheck::JsConsoleHijack]),
        "{plan:#?}"
    );
    let patched: String = applied(&source, &plan);
    assert_eq!(boa_stdout(&boa(&patched, &[])), Some(clean.stdout));
    assert_wrong_original_bytes_are_refused(&source, &plan);
}

#[test]
fn real_obfuscator_io_debug_protection_plan_comments_out_the_constructed_traps() {
    let clean: NodeRun = run_node(
        &[&repo_path("corpus/src/javascript/obfuscator-io-high.js")],
        &[],
    );
    let source: String = read(&repo_path(
        "corpus/src/javascript/obfuscator-io-samples/controls/debugProtection.js",
    ));
    let plan: NeutralizationPlan = plan_for(&source);
    assert_eq!(
        checks(&plan),
        BTreeSet::from([RuntimeCheck::JsDebuggerTrap]),
        "{plan:#?}"
    );
    assert!(plan.refusals.is_empty(), "{plan:#?}");
    let patched: String = applied(&source, &plan);
    assert!(!patched.contains("'debu'") && !patched.contains("while\\x20(true)"));
    assert_eq!(boa_stdout(&boa(&patched, &[])), Some(clean.stdout));
    let replanned: NeutralizationPlan = plan_for(&patched);
    assert!(replanned.patches.is_empty(), "{replanned:#?}");
}

#[test]
fn real_jsconfuser_integrity_plan_lets_an_edited_helper_run() {
    let reference: NodeRun = run_node(
        &[&repo_path("corpus/js/jsconfuser/recovery/src_integrity.js")],
        &["3", "4"],
    );
    assert_eq!(reference.stdout, "7\n12\n");
    let source: String = read(&repo_path(
        "corpus/js/jsconfuser/recovery/obf_integrity.real.js",
    ));
    let edit = |text: &str| -> String {
        assert_eq!(text.matches("return a+b}").count(), 1);
        text.replace("return a+b}", "return b+a}")
    };

    for program in [source.clone(), edit(&source)] {
        let trapped: common::EvalOutcome = boa(&program, &["3", "4"]);
        assert!(
            matches!(trapped.terminal, common::Terminal::ExecutionLimitExceeded),
            "the bounded engine renders function source differently from node, so the digest misses and the integrity loop must spin: {:?}",
            trapped.terminal
        );
    }

    let plan: NeutralizationPlan = plan_for(&source);
    assert_eq!(
        checks(&plan),
        BTreeSet::from([RuntimeCheck::JsIntegrityHash]),
        "{plan:#?}"
    );
    assert_eq!(plan.patches.len(), 2, "{plan:#?}");
    let patched: String = applied(&source, &plan);
    for program in [patched.clone(), edit(&patched)] {
        let unlocked: common::EvalOutcome = boa(&program, &["3", "4"]);
        assert_eq!(
            boa_stdout(&unlocked),
            Some(reference.stdout.clone()),
            "{:?}",
            unlocked.terminal
        );
    }
    assert_wrong_original_bytes_are_refused(&source, &plan);
}

#[test]
fn a_long_test_with_code_on_both_branches_is_refused_by_name() {
    let source: &str = "function go(){ if (typeof process !== 'undefined' && process.versions != null && process.versions.node != null) { throw new Error('node'); } else { run(); } }";
    let plan: NeutralizationPlan = plan_for(source);
    assert!(plan.patches.is_empty(), "{plan:#?}");
    assert_eq!(plan.refusals.len(), 1, "{plan:#?}");
    assert_eq!(plan.refusals[0].check, RuntimeCheck::JsHostEnvironmentProbe);
    assert!(plan.refusals[0].reason.contains("patch cap"));
}

#[test]
fn a_quiet_server_rendering_guard_is_not_a_host_probe() {
    let source: &str = "function mount(){ if (typeof document === 'undefined') return; document.body.append('x'); }";
    let plan: NeutralizationPlan = plan_for(source);
    assert!(
        plan.patches.is_empty() && plan.refusals.is_empty(),
        "{plan:#?}"
    );
}

#[test]
fn hostile_scripts_get_typed_errors_and_never_panic() {
    let oversized: String = " ".repeat(MAX_SCAN_BYTES + 1);
    assert!(matches!(
        plan_js_neutralization(&oversized),
        Err(JsNeutralizeError::TooLarge { .. })
    ));
    let deep: String = format!("{}1{}", "(".repeat(5000), ")".repeat(5000));
    assert!(matches!(
        plan_js_neutralization(&deep),
        Err(JsNeutralizeError::TooDeep)
    ));
    assert!(matches!(
        plan_js_neutralization("if (typeof window === { ;"),
        Err(JsNeutralizeError::Parse(_))
    ));
    let many: String = "debugger;\n".repeat(MAX_SITES + 1);
    assert!(matches!(
        plan_js_neutralization(&many),
        Err(JsNeutralizeError::TooManySites { .. })
    ));
    let at_cap: String = "debugger;\n".repeat(MAX_SITES);
    assert_eq!(plan_for(&at_cap).patches.len(), MAX_SITES);

    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let alphabet: &[u8] = b"if(typeof window===\"undefined\"){return;}debugger;Function('debu'+'gger')x[y]=z||{};0x74 7 116 5 101 3 117 0 100\n";
    for _ in 0..512 {
        let mut text: Vec<u8> = Vec::new();
        for _ in 0..256 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            text.push(alphabet[(state >> 33) as usize % alphabet.len()]);
        }
        let script: String = String::from_utf8(text).expect("ASCII alphabet");
        if let Ok(plan) = plan_js_neutralization(&script) {
            let out: Applied =
                apply(script.as_bytes(), &plan, &Selection::All).expect("a made plan applies");
            assert_eq!(out.bytes.len(), script.len());
        }
    }
}

#[test]
fn recovery_strips_the_real_console_hijack_and_every_line_prints_again() {
    let clean: NodeRun = run_node(
        &[&repo_path("corpus/src/javascript/obfuscator-io-high.js")],
        &[],
    );
    let source: String = read(&repo_path(
        "corpus/src/javascript/obfuscator-io-samples/presets/low.js",
    ));
    let recovered: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(&source, &ObfuscatorIoOptions::all()).expect("recovery");
    let replanned: NeutralizationPlan = plan_for(&recovered.source);
    assert!(
        !replanned.checks().contains(&RuntimeCheck::JsConsoleHijack),
        "the recovered script still overwrites console: {}",
        recovered.source
    );
    assert_eq!(
        boa_stdout(&boa(&recovered.source, &[])),
        Some(clean.stdout),
        "{}",
        recovered.source
    );

    let authored: String = read(&fixture("console_hijack.obfuscator-io.js"));
    let hijack: &str = authored.lines().next().expect("the hijack statement");
    let mutated: String = format!("{hijack}\n{}", recovered.source);
    assert_eq!(
        boa_stdout(&boa(&mutated, &[])).as_deref(),
        Some(""),
        "re-inserting the hijack must silence the recovered script"
    );
}
