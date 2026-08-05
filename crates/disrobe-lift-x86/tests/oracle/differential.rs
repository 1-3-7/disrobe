use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_lift_x86::decode_block_x86;
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, RflagsBits};
use sha2::{Digest as _, Sha256};

use crate::machine::{
    ADJUST_BIT, CARRY_BIT, GPR_COUNT, IMAGE_BASE, OBSERVED_FLAGS, OVERFLOW_BIT, Outcome,
    PARITY_BIT, SIGN_BIT, StateDelta, ZERO_BIT, flag_label, is_address_fault, register_label,
};
use crate::{corpus_path, evaluator, generator};

const REFERENCE_TOOL: &str = "the python unicorn 2.1.4 package";
const REFERENCE_VERSION: &str = "2.1.4";
const CORPUS_NAME: &str = "x86_64_unicorn.tsv";
const WORKER_COUNT: usize = 4;
const SWEEP_BUDGET: Duration = Duration::from_mins(3);
const REFERENCE_TIMEOUT: Duration = Duration::from_mins(15);
const REFERENCE_CAPTURE_BYTES: usize = 1 << 22;
const DIVERGENCE_SAMPLE: usize = 200;
const COMPARED_CASE_FLOOR: usize = 4992;
const COMPARED_MNEMONIC_FLOOR: usize = 122;

const OUT_OF_SCOPE_MNEMONICS: [&str; 11] = [
    "andps",
    "movaps",
    "movd",
    "movq",
    "movss",
    "movups",
    "orps",
    "pxor",
    "xorpd",
    "xorps",
    "movsd_xmm",
];

const UNDEFINED_FLAG_TABLE: [(&str, u16); 26] = [
    (
        "bsf",
        (1 << CARRY_BIT)
            | (1 << PARITY_BIT)
            | (1 << ADJUST_BIT)
            | (1 << SIGN_BIT)
            | (1 << OVERFLOW_BIT),
    ),
    (
        "bsr",
        (1 << CARRY_BIT)
            | (1 << PARITY_BIT)
            | (1 << ADJUST_BIT)
            | (1 << SIGN_BIT)
            | (1 << OVERFLOW_BIT),
    ),
    (
        "bt",
        (1 << PARITY_BIT) | (1 << ADJUST_BIT) | (1 << SIGN_BIT) | (1 << OVERFLOW_BIT),
    ),
    (
        "btc",
        (1 << PARITY_BIT) | (1 << ADJUST_BIT) | (1 << SIGN_BIT) | (1 << OVERFLOW_BIT),
    ),
    (
        "btr",
        (1 << PARITY_BIT) | (1 << ADJUST_BIT) | (1 << SIGN_BIT) | (1 << OVERFLOW_BIT),
    ),
    (
        "bts",
        (1 << PARITY_BIT) | (1 << ADJUST_BIT) | (1 << SIGN_BIT) | (1 << OVERFLOW_BIT),
    ),
    (
        "div",
        (1 << CARRY_BIT)
            | (1 << PARITY_BIT)
            | (1 << ADJUST_BIT)
            | (1 << ZERO_BIT)
            | (1 << SIGN_BIT)
            | (1 << OVERFLOW_BIT),
    ),
    (
        "idiv",
        (1 << CARRY_BIT)
            | (1 << PARITY_BIT)
            | (1 << ADJUST_BIT)
            | (1 << ZERO_BIT)
            | (1 << SIGN_BIT)
            | (1 << OVERFLOW_BIT),
    ),
    (
        "imul",
        (1 << PARITY_BIT) | (1 << ADJUST_BIT) | (1 << ZERO_BIT) | (1 << SIGN_BIT),
    ),
    (
        "mul",
        (1 << PARITY_BIT) | (1 << ADJUST_BIT) | (1 << ZERO_BIT) | (1 << SIGN_BIT),
    ),
    ("and", 1 << ADJUST_BIT),
    ("or", 1 << ADJUST_BIT),
    ("test", 1 << ADJUST_BIT),
    ("xor", 1 << ADJUST_BIT),
    ("rcl", 1 << OVERFLOW_BIT),
    ("rcr", 1 << OVERFLOW_BIT),
    ("rol", 1 << OVERFLOW_BIT),
    ("ror", 1 << OVERFLOW_BIT),
    ("sal", (1 << ADJUST_BIT) | (1 << OVERFLOW_BIT)),
    ("sar", (1 << ADJUST_BIT) | (1 << OVERFLOW_BIT)),
    ("shl", (1 << ADJUST_BIT) | (1 << OVERFLOW_BIT)),
    ("shr", (1 << ADJUST_BIT) | (1 << OVERFLOW_BIT)),
    ("shld", (1 << ADJUST_BIT) | (1 << OVERFLOW_BIT)),
    ("shrd", (1 << ADJUST_BIT) | (1 << OVERFLOW_BIT)),
    (
        "lzcnt",
        (1 << PARITY_BIT) | (1 << ADJUST_BIT) | (1 << SIGN_BIT) | (1 << OVERFLOW_BIT),
    ),
    (
        "tzcnt",
        (1 << PARITY_BIT) | (1 << ADJUST_BIT) | (1 << SIGN_BIT) | (1 << OVERFLOW_BIT),
    ),
];

const RFLAGS_POSITIONS: [(u32, u32); 6] = [
    (RflagsBits::CF, CARRY_BIT),
    (RflagsBits::PF, PARITY_BIT),
    (RflagsBits::AF, ADJUST_BIT),
    (RflagsBits::ZF, ZERO_BIT),
    (RflagsBits::SF, SIGN_BIT),
    (RflagsBits::OF, OVERFLOW_BIT),
];

#[derive(Clone, Debug, Default)]
struct Tally {
    run: usize,
    agree: usize,
    diverge: usize,
    faults: usize,
    reference_absent: usize,
    unmapped: usize,
    reference_deviation: usize,
    undefined_result: usize,
    not_modeled: usize,
}

#[derive(Clone, Debug)]
enum Verdict {
    Agree,
    Faulted,
    Diverge(String),
    ReferenceAbsent(String),
    UnmappedAccess(String),
    ReferenceDeviation(&'static str),
    UndefinedResult(&'static str),
    NotModeled(String),
}

#[derive(Clone, Debug)]
struct CaseReport {
    mnemonic: String,
    verdict: Verdict,
    undefined: u16,
    declared: u16,
    claimed: bool,
}

#[test]
fn lifted_state_matches_committed_cpu_reference() {
    let started: Instant = Instant::now();
    let image: Vec<u8> = generator::base_image();
    let cases: Vec<generator::Case> = generator::build_cases(&image);
    assert!(!cases.is_empty());
    assert!(cases.len() <= generator::MAX_CASES);
    let request: String = render_request(&cases);
    let committed: String = fs::read_to_string(corpus_path(CORPUS_NAME)).unwrap_or_default();
    assert!(
        !committed.is_empty(),
        "the committed reference corpus {CORPUS_NAME} is missing"
    );
    let (header, outcomes): (BTreeMap<String, String>, Vec<Outcome>) = parse_corpus(&committed);
    assert_eq!(
        header.get("unicorn").map(String::as_str),
        Some(REFERENCE_VERSION),
        "the committed corpus was produced by a different reference version"
    );
    assert_eq!(
        header.get("digest").map(String::as_str),
        Some(request_digest(&request).as_str()),
        "the generated case stream no longer matches the committed corpus; regenerate it with {REFERENCE_TOOL}"
    );
    assert_eq!(outcomes.len(), cases.len());

    let reports: Vec<CaseReport> = grade(&cases, &outcomes);
    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    let mut divergences: Vec<String> = Vec::new();
    let mut observed_undefined: BTreeMap<String, u16> = BTreeMap::new();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut deviations: BTreeMap<String, usize> = BTreeMap::new();
    let mut undefined: BTreeMap<String, usize> = BTreeMap::new();
    let mut absences: BTreeMap<String, usize> = BTreeMap::new();
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    let mut graded: BTreeSet<String> = BTreeSet::new();
    for report in &reports {
        let tally: &mut Tally = tallies.entry(report.mnemonic.clone()).or_default();
        tally.run = tally.run.saturating_add(1);
        if report.claimed {
            let _: bool = claimed.insert(report.mnemonic.clone());
        }
        if matches!(
            report.verdict,
            Verdict::Agree | Verdict::Faulted | Verdict::Diverge(_)
        ) {
            let _: bool = graded.insert(report.mnemonic.clone());
        }
        match &report.verdict {
            Verdict::Agree => tally.agree = tally.agree.saturating_add(1),
            Verdict::Faulted => {
                tally.agree = tally.agree.saturating_add(1);
                tally.faults = tally.faults.saturating_add(1);
            }
            Verdict::Diverge(detail) => {
                tally.diverge = tally.diverge.saturating_add(1);
                if divergences.len() < DIVERGENCE_SAMPLE {
                    divergences.push(detail.clone());
                }
            }
            Verdict::ReferenceAbsent(reason) => {
                tally.reference_absent = tally.reference_absent.saturating_add(1);
                let seen: &mut usize = absences.entry(reason.clone()).or_default();
                *seen = seen.saturating_add(1);
            }
            Verdict::UnmappedAccess(reason) => {
                tally.unmapped = tally.unmapped.saturating_add(1);
                let seen: &mut usize = absences.entry(reason.clone()).or_default();
                *seen = seen.saturating_add(1);
            }
            Verdict::ReferenceDeviation(reason) => {
                tally.reference_deviation = tally.reference_deviation.saturating_add(1);
                let seen: &mut usize = deviations.entry((*reason).to_owned()).or_default();
                *seen = seen.saturating_add(1);
            }
            Verdict::UndefinedResult(reason) => {
                tally.undefined_result = tally.undefined_result.saturating_add(1);
                let seen: &mut usize = undefined.entry((*reason).to_owned()).or_default();
                *seen = seen.saturating_add(1);
            }
            Verdict::NotModeled(reason) => {
                tally.not_modeled = tally.not_modeled.saturating_add(1);
                let seen: &mut usize = reasons.entry(reason.clone()).or_default();
                *seen = seen.saturating_add(1);
            }
        }
        if !matches!(
            report.verdict,
            Verdict::Agree | Verdict::Faulted | Verdict::Diverge(_)
        ) {
            continue;
        }
        assert_eq!(
            report.undefined & !report.declared,
            0,
            "{} marks a flag undefined that the declared table omits",
            report.mnemonic
        );
        let slot: &mut u16 = observed_undefined
            .entry(report.mnemonic.clone())
            .or_default();
        *slot |= report.undefined;
    }
    for (mnemonic, declared) in UNDEFINED_FLAG_TABLE {
        let Some(observed): Option<&u16> = observed_undefined.get(mnemonic) else {
            continue;
        };
        assert_eq!(
            *observed, declared,
            "the declared undefined-flag mask for {mnemonic} is wider than the decoder tables allow"
        );
    }

    print_table(&tallies);
    for (reason, count) in &reasons {
        println!("x86-64 differential unevaluable effect: {reason} on {count} cases");
    }
    for (reason, count) in &absences {
        println!(
            "x86-64 differential uncompared for a reference reason on {count} cases: {reason}"
        );
    }
    for (reason, count) in &deviations {
        println!("x86-64 differential reference deviation on {count} cases: {reason}");
    }
    for (reason, count) in &undefined {
        println!("x86-64 differential declined {count} architecturally undefined cases: {reason}");
    }
    let unreached: Vec<&String> = claimed.difference(&graded).collect();
    println!(
        "x86-64 executed differential: {}/{} mnemonics the lifter models are graded over {} cases against {REFERENCE_TOOL}, {} mnemonics reached in total",
        claimed.intersection(&graded).count(),
        claimed.len(),
        reports.len(),
        tallies.len()
    );
    println!("x86-64 differential unreached modeled mnemonics: {unreached:?}");
    let compared: usize = reports
        .iter()
        .filter(|report: &&CaseReport| {
            matches!(
                report.verdict,
                Verdict::Agree | Verdict::Faulted | Verdict::Diverge(_)
            )
        })
        .count();
    let uncompared: usize = tallies
        .values()
        .map(|tally: &Tally| {
            tally.reference_absent
                + tally.unmapped
                + tally.reference_deviation
                + tally.undefined_result
                + tally.not_modeled
        })
        .sum();
    println!(
        "x86-64 differential compared {compared} cases over {} mnemonics; {uncompared} cases carry a stated reason for not being compared",
        graded.len()
    );
    assert_eq!(
        compared + uncompared,
        reports.len(),
        "every case must either be compared or carry a stated reason"
    );
    assert!(
        compared >= COMPARED_CASE_FLOOR,
        "only {compared} cases reached a comparison, below the {COMPARED_CASE_FLOOR} the committed corpus measures"
    );
    assert!(
        graded.len() >= COMPARED_MNEMONIC_FLOOR,
        "only {} mnemonics reached a comparison, below the {COMPARED_MNEMONIC_FLOOR} the committed corpus measures",
        graded.len()
    );
    assert!(
        unreached.is_empty(),
        "these mnemonics the lifter models reached no comparison: {unreached:?}"
    );
    assert!(
        divergences.is_empty(),
        "lifted semantics disagree with the reference on {} cases:\n{}",
        reports
            .iter()
            .filter(|report: &&CaseReport| matches!(report.verdict, Verdict::Diverge(_)))
            .count(),
        divergences.join("\n")
    );
    let elapsed: Duration = started.elapsed();
    assert!(
        elapsed < SWEEP_BUDGET,
        "the sweep took {elapsed:?} which exceeds the {SWEEP_BUDGET:?} budget"
    );
}

#[test]
fn live_cpu_reference_reproduces_the_committed_corpus() {
    let Some(python): Option<PathBuf> = find_python_with_unicorn() else {
        eprintln!(
            "x86-64 executed differential regeneration skipped because {REFERENCE_TOOL} is unavailable"
        );
        return;
    };
    let image: Vec<u8> = generator::base_image();
    let cases: Vec<generator::Case> = generator::build_cases(&image);
    let request: String = render_request(&cases);
    let created: std::io::Result<ScratchDir> = ScratchDir::create("disrobe-lift-x86-differential");
    assert!(created.is_ok(), "{created:?}");
    let Ok(scratch): std::io::Result<ScratchDir> = created else {
        return;
    };
    let image_path: PathBuf = scratch.path().join("image.bin");
    let cases_path: PathBuf = scratch.path().join("cases.tsv");
    let output_path: PathBuf = scratch.path().join("results.tsv");
    let write_image: std::io::Result<()> = fs::write(&image_path, &image);
    assert!(write_image.is_ok(), "{write_image:?}");
    let write_cases: std::io::Result<()> = fs::write(&cases_path, request.as_bytes());
    assert!(write_cases.is_ok(), "{write_cases:?}");
    let script: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("unicorn_oracle.py");
    let arguments: [OsString; 4] = [
        script.as_os_str().to_owned(),
        image_path.as_os_str().to_owned(),
        cases_path.as_os_str().to_owned(),
        output_path.as_os_str().to_owned(),
    ];
    let captured: std::io::Result<Option<CapturedOutput>> = run_captured(
        &python,
        &arguments,
        REFERENCE_TIMEOUT,
        REFERENCE_CAPTURE_BYTES,
    );
    assert!(
        matches!(captured, Ok(Some(_))),
        "the reference did not finish inside {REFERENCE_TIMEOUT:?}"
    );
    let Ok(Some(result)): std::io::Result<Option<CapturedOutput>> = captured else {
        return;
    };
    assert_eq!(
        result.exit_code,
        Some(0),
        "reference failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let produced: String = fs::read_to_string(&output_path).unwrap_or_default();
    let committed: String = fs::read_to_string(corpus_path(CORPUS_NAME)).unwrap_or_default();
    if let Some(directory) = env::var_os("DISROBE_X86_DIFFERENTIAL_OUT") {
        let target: PathBuf = PathBuf::from(directory);
        let _: std::io::Result<()> = fs::create_dir_all(&target);
        let _: std::io::Result<()> = fs::write(target.join(CORPUS_NAME), produced.as_bytes());
        let _: std::io::Result<()> = fs::write(target.join("cases.tsv"), request.as_bytes());
        let _: std::io::Result<()> = fs::write(target.join("image.bin"), &image);
    }
    let close: std::io::Result<()> = scratch.close();
    assert!(close.is_ok(), "{close:?}");
    assert!(!produced.is_empty(), "the reference produced no results");
    assert_eq!(
        produced.replace("\r\n", "\n"),
        committed.replace("\r\n", "\n"),
        "the live reference no longer reproduces the committed corpus"
    );
}

#[test]
fn every_modeled_mnemonic_in_the_committed_text_is_graded() {
    let bytes: Vec<u8> = fs::read(corpus_path("x86_64_oracle_o2.text")).unwrap_or_default();
    assert!(!bytes.is_empty());
    let block: DecodedBlock = decode_block_x86(&bytes, 0, 64);
    let mut modeled: BTreeSet<String> = BTreeSet::new();
    for instruction in &block.instructions {
        if instruction.status == DecodeStatus::Supported {
            let _: bool = modeled.insert(instruction.mnemonic.clone());
        }
    }
    let image: Vec<u8> = generator::base_image();
    let cases: Vec<generator::Case> = generator::build_cases(&image);
    let mut graded: BTreeSet<String> = BTreeSet::new();
    for case in &cases {
        let _: bool = graded.insert(case.mnemonic.clone());
    }
    let missing: Vec<String> = modeled
        .difference(&graded)
        .filter(|name: &&String| !OUT_OF_SCOPE_MNEMONICS.contains(&name.as_str()))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "these modeled mnemonics reach no differential case: {missing:?}"
    );
    println!(
        "x86-64 differential coverage: {}/{} mnemonics modeled in the committed text are graded, {} declared out of scope",
        modeled.len().saturating_sub(missing.len()),
        modeled.len(),
        OUT_OF_SCOPE_MNEMONICS.len()
    );
}

fn request_digest(request: &str) -> String {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(request.as_bytes());
    render_hex(&hasher.finalize())
}

fn render_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::new(), |mut text: String, byte: &u8| {
            let _: Result<(), std::fmt::Error> = write!(text, "{byte:02x}");
            text
        })
}

fn render_request(cases: &[generator::Case]) -> String {
    let mut rendered: String = String::new();
    for (index, case) in cases.iter().enumerate() {
        let _: Result<(), std::fmt::Error> = writeln!(rendered, "{}", case.render_request(index));
    }
    rendered
}

fn parse_corpus(text: &str) -> (BTreeMap<String, String>, Vec<Outcome>) {
    let mut header: BTreeMap<String, String> = BTreeMap::new();
    let mut outcomes: Vec<Outcome> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('#') {
            if let Some((key, value)) = rest.trim().split_once(' ') {
                let _: Option<String> = header.insert(key.to_owned(), value.to_owned());
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let Some((status, payload)): Option<(&str, &str)> = line.split_once('\t') else {
            continue;
        };
        if let Some(outcome) = Outcome::parse(status, payload) {
            outcomes.push(outcome);
        }
    }
    (header, outcomes)
}

fn grade(cases: &[generator::Case], outcomes: &[Outcome]) -> Vec<CaseReport> {
    let chunk: usize = cases.len().div_ceil(WORKER_COUNT).max(1);
    let mut collected: Vec<Vec<CaseReport>> = Vec::new();
    thread::scope(|scope: &thread::Scope<'_, '_>| {
        let mut handles: Vec<thread::ScopedJoinHandle<'_, Vec<CaseReport>>> = Vec::new();
        for (position, window) in cases.chunks(chunk).enumerate() {
            let start: usize = position.saturating_mul(chunk);
            let slice: &[Outcome] = outcomes.get(start..start + window.len()).unwrap_or(&[]);
            handles.push(scope.spawn(move || {
                window
                    .iter()
                    .zip(slice)
                    .map(|(case, reference): (&generator::Case, &Outcome)| {
                        grade_case(case, reference)
                    })
                    .collect()
            }));
        }
        for handle in handles {
            collected.push(handle.join().unwrap_or_default());
        }
    });
    collected.into_iter().flatten().collect()
}

fn grade_case(case: &generator::Case, reference: &Outcome) -> CaseReport {
    let declared: u16 = declared_undefined(&case.mnemonic);
    let architectural: u16 = architectural_undefined(case);
    let block: DecodedBlock = decode_block_x86(&case.bytes, case.state.rip, 64);
    let Some(lifted): Option<&PcodeInstr> = block.instructions.first() else {
        return CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::NotModeled("the lifter produced no instruction".to_owned()),
            undefined: 0,
            declared,
            claimed: false,
        };
    };
    let claimed: bool = lifted.status == DecodeStatus::Supported;
    if block.instructions.len() != 1 || lifted.length != case.bytes.len() {
        return CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::Diverge(format!(
                "{} decode length {} but the reference consumed {} ({})",
                describe(case),
                lifted.length,
                case.bytes.len(),
                case.code_name()
            )),
            undefined: architectural,
            declared,
            claimed,
        };
    }
    if let Outcome::Rejected(reason) = reference {
        return CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::ReferenceAbsent(format!(
                "the reference refused the encoding ({reason})"
            )),
            undefined: architectural,
            declared,
            claimed,
        };
    }
    if let Outcome::Faulted(reason) = reference
        && is_address_fault(reason)
    {
        return CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::UnmappedAccess(format!(
                "the generated address left the mapped image ({reason})"
            )),
            undefined: architectural,
            declared,
            claimed,
        };
    }
    if let Some(reason) = reference_deviation(&case.bytes) {
        return CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::ReferenceDeviation(reason),
            undefined: architectural,
            declared,
            claimed,
        };
    }
    if let Some(reason) = undefined_result(case) {
        return CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::UndefinedResult(reason),
            undefined: architectural,
            declared,
            claimed,
        };
    }
    let evaluation: evaluator::Evaluation =
        evaluator::evaluate(&lifted.ops, &case.state, case.next_address);
    match (evaluation, reference) {
        (evaluator::Evaluation::Unmodeled(reason), _) => CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::NotModeled(reason),
            undefined: architectural,
            declared,
            claimed,
        },
        (evaluator::Evaluation::Faulted, Outcome::Faulted(_)) => CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::Faulted,
            undefined: architectural,
            declared,
            claimed,
        },
        (evaluator::Evaluation::Faulted, Outcome::Completed(_)) => CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::Diverge(format!(
                "{} the lifted form faulted while the reference completed",
                describe(case)
            )),
            undefined: architectural,
            declared,
            claimed,
        },
        (evaluator::Evaluation::Completed(_, _), Outcome::Faulted(_)) => CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::Diverge(format!(
                "{} the reference faulted while the lifted form completed",
                describe(case)
            )),
            undefined: architectural,
            declared,
            claimed,
        },
        (evaluator::Evaluation::Completed(state, marks), Outcome::Completed(expected)) => {
            let mut mask: u16 = architectural;
            for bit in &marks {
                mask |= 1u16.checked_shl(*bit).unwrap_or(0);
            }
            let produced: StateDelta = StateDelta::between(&case.state, &state);
            let verdict: Verdict = compare(case, expected, &produced, mask);
            CaseReport {
                mnemonic: case.mnemonic.clone(),
                verdict,
                undefined: mask & OBSERVED_FLAGS,
                declared,
                claimed,
            }
        }
        (_, Outcome::Rejected(reason)) => CaseReport {
            mnemonic: case.mnemonic.clone(),
            verdict: Verdict::ReferenceAbsent(format!(
                "the reference refused the encoding ({reason})"
            )),
            undefined: architectural,
            declared,
            claimed,
        },
    }
}

fn compare(
    case: &generator::Case,
    expected: &StateDelta,
    produced: &StateDelta,
    mask: u16,
) -> Verdict {
    if expected.rip != produced.rip {
        return Verdict::Diverge(format!(
            "{} field rip expected {:#x} produced {:#x}",
            describe(case),
            expected.rip,
            produced.rip
        ));
    }
    let expected_flags: u16 = expected.flags & !mask & OBSERVED_FLAGS;
    let produced_flags: u16 = produced.flags & !mask & OBSERVED_FLAGS;
    if expected_flags != produced_flags {
        let differing: u16 = expected_flags ^ produced_flags;
        let names: Vec<&str> = (0..16)
            .filter(|bit: &u32| differing & 1u16.checked_shl(*bit).unwrap_or(0) != 0)
            .map(flag_label)
            .collect();
        return Verdict::Diverge(format!(
            "{} field flags {:?} expected {expected_flags:#x} produced {produced_flags:#x}",
            describe(case),
            names
        ));
    }
    for index in 0..GPR_COUNT {
        let base: u64 = case.state.registers.get(index).copied().unwrap_or(0);
        let expected_value: u64 = expected.registers.get(&index).copied().unwrap_or(base);
        let produced_value: u64 = produced.registers.get(&index).copied().unwrap_or(base);
        if expected_value != produced_value {
            return Verdict::Diverge(format!(
                "{} field {} expected {expected_value:#x} produced {produced_value:#x}",
                describe(case),
                register_label(index)
            ));
        }
    }
    let mut addresses: BTreeSet<u64> = expected.memory.keys().copied().collect();
    addresses.extend(produced.memory.keys().copied());
    for address in addresses {
        let offset: usize = usize::try_from(address.wrapping_sub(IMAGE_BASE)).unwrap_or(0);
        let base: u8 = case.state.memory.get(offset).copied().unwrap_or(0);
        let expected_byte: u8 = expected.memory.get(&address).copied().unwrap_or(base);
        let produced_byte: u8 = produced.memory.get(&address).copied().unwrap_or(base);
        if expected_byte != produced_byte {
            return Verdict::Diverge(format!(
                "{} field memory[{address:#x}] expected {expected_byte:#04x} produced {produced_byte:#04x}",
                describe(case)
            ));
        }
    }
    Verdict::Agree
}

fn describe(case: &generator::Case) -> String {
    let encoded: String = render_hex(&case.bytes);
    let registers: String = (0..GPR_COUNT)
        .map(|index: usize| {
            format!(
                "{}={:#x}",
                register_label(index),
                case.state.registers.get(index).copied().unwrap_or(0)
            )
        })
        .collect::<Vec<String>>()
        .join(" ");
    format!(
        "{} [{}] seed {:#018x} bytes {encoded} flags {:#x} {registers}:",
        case.mnemonic,
        case.code_name(),
        case.seed,
        case.state.flags
    )
}

fn declared_undefined(mnemonic: &str) -> u16 {
    UNDEFINED_FLAG_TABLE
        .iter()
        .find(|(name, _): &&(&str, u16)| *name == mnemonic)
        .map_or(0, |(_, mask): &(&str, u16)| *mask)
}

fn reference_deviation(bytes: &[u8]) -> Option<&'static str> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, IMAGE_BASE, DecoderOptions::NONE);
    let decoded: Instruction = decoder.decode();
    if decoded.code() == Code::Retnq_imm16 && decoded.immediate16() >= 0x8000 {
        return Some(
            "the reference sign-extends the stack-release immediate of a near return while the vendor pseudocode and the Ghidra model both add it as an unsigned byte count",
        );
    }
    if matches!(decoded.mnemonic(), Mnemonic::Shld | Mnemonic::Shrd)
        && decoded.op_kind(0) == OpKind::Memory
        && decoded.is_ip_rel_memory_operand()
        && decoded.memory_size().size() == 2
    {
        return Some(
            "the reference stores one byte of a 16-bit double shift whose destination is addressed relative to the instruction pointer, and its result varies with memory outside the operand, while its own absolute-address form and the Ghidra model both agree with the lifted semantics",
        );
    }
    None
}

fn undefined_result(case: &generator::Case) -> Option<&'static str> {
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(64, &case.bytes, IMAGE_BASE, DecoderOptions::NONE);
    let decoded: Instruction = decoder.decode();
    if !matches!(decoded.mnemonic(), Mnemonic::Shld | Mnemonic::Shrd) {
        return None;
    }
    let width: usize = if decoded.op_kind(0) == OpKind::Memory {
        decoded.memory_size().size()
    } else {
        decoded.op_register(0).size()
    };
    let masked: u64 = shift_count(case, &decoded)?;
    (width == 2 && masked > 16).then_some(
        "a double shift whose masked count exceeds a 16-bit operand size has an architecturally undefined result",
    )
}

fn architectural_undefined(case: &generator::Case) -> u16 {
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(64, &case.bytes, IMAGE_BASE, DecoderOptions::NONE);
    let decoded: Instruction = decoder.decode();
    let reported: u32 = decoded.rflags_undefined();
    let mut mask: u16 = 0;
    for (source, position) in RFLAGS_POSITIONS {
        if reported & source != 0 {
            mask |= 1u16.checked_shl(position).unwrap_or(0);
        }
    }
    match shift_count(case, &decoded) {
        Some(0) => 0,
        Some(1) => mask & !(1 << OVERFLOW_BIT),
        _ => mask,
    }
}

fn shift_count(case: &generator::Case, decoded: &Instruction) -> Option<u64> {
    let doubled: bool = matches!(decoded.mnemonic(), Mnemonic::Shld | Mnemonic::Shrd);
    if !doubled
        && !matches!(
            decoded.mnemonic(),
            Mnemonic::Shl
                | Mnemonic::Sal
                | Mnemonic::Shr
                | Mnemonic::Sar
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Rcl
                | Mnemonic::Rcr
        )
    {
        return None;
    }
    let width: usize = if decoded.op_kind(0) == OpKind::Memory {
        decoded.memory_size().size()
    } else {
        decoded.op_register(0).size()
    };
    let operand: u32 = u32::from(doubled) + 1;
    let raw: u64 = if decoded.op_kind(operand) == OpKind::Register {
        case.state.registers.get(1).copied().unwrap_or(0) & 0xff
    } else {
        u64::from(decoded.immediate8())
    };
    Some(raw & if width == 8 { 0x3f } else { 0x1f })
}

fn print_table(tallies: &BTreeMap<String, Tally>) {
    println!(
        "mnemonic\trun\tagree\tdiverge\tfault\treference-absent\tunmapped\treference-deviation\tundefined\tnot-modeled"
    );
    for (mnemonic, tally) in tallies {
        println!(
            "{mnemonic}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            tally.run,
            tally.agree,
            tally.diverge,
            tally.faults,
            tally.reference_absent,
            tally.unmapped,
            tally.reference_deviation,
            tally.undefined_result,
            tally.not_modeled
        );
    }
}

fn find_python_with_unicorn() -> Option<PathBuf> {
    let names: [&str; 2] = if cfg!(windows) {
        ["python", "python3"]
    } else {
        ["python3", "python"]
    };
    for name in names {
        let Some(candidate): Option<PathBuf> = locate(name) else {
            continue;
        };
        let mut command: Command = Command::new(&candidate);
        command.args([
            OsString::from("-c"),
            OsString::from(format!(
                "import unicorn; raise SystemExit(0 if unicorn.__version__ == '{REFERENCE_VERSION}' else 1)"
            )),
        ]);
        if matches!(command.output(), Ok(result) if result.status.success()) {
            return Some(candidate);
        }
    }
    None
}

fn locate(name: &str) -> Option<PathBuf> {
    let executable: String = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let path: OsString = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory: PathBuf| directory.join(&executable))
        .find(|candidate: &PathBuf| candidate.is_file())
}
