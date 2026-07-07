#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::{EvalOutcome, Terminal, eval_outcome, eval_outcome_bare, eval_outcome_with_argv};
use disrobe_pass_js_deob::{
    DeobOptions, Detection, JsObfuscator, OBFUSCATOR_IO_MAX_PASS_CEILING, ObfuscatorIoControl,
    ObfuscatorIoOptions, ObfuscatorIoOutput, deobfuscate_all, detect, obfuscator_io_deobfuscate,
};

const DIFFERENTIAL_FLOOR: usize = 36;
const EVAL_TIMEOUT: Duration = Duration::from_secs(12);
const HIGH_CLEAN: &str = "src/javascript/obfuscator-io-high.js";

struct Sample {
    name: &'static str,
    obf: &'static str,
    src: &'static str,
    argv_battery: &'static [&'static [&'static str]],
}

const NO_ARGS: &[&[&str]] = &[&[]];
const CLASSIFY_BATTERY: &[&[&str]] = &[
    &["150"],
    &["101"],
    &["100"],
    &["50"],
    &["11"],
    &["10"],
    &["5"],
    &["0"],
];
const INTEGRITY_BATTERY: &[&[&str]] = &[
    &["2", "3"],
    &["10", "20"],
    &["0", "0"],
    &["-5", "7"],
    &["7", "6"],
];
const RUNTIME_BATTERY: &[&[&str]] = &[
    &["10"],
    &["100"],
    &["0"],
    &["-7"],
    &["42"],
    &["1"],
    &["999"],
];
const STRINGS_BATTERY: &[&[&str]] = &[&["world"], &["planet"], &["sun"], &["a"]];
const LOOP_BATTERY: &[&[&str]] = &[
    &["10"],
    &["1"],
    &["0"],
    &["7"],
    &["100"],
    &["3"],
    &["25"],
    &["50"],
];

const SAMPLES: &[Sample] = &[
    Sample {
        name: "javascript-obfuscator/gauntlet",
        obf: "js/javascript-obfuscator/gauntlet-obfuscated.js",
        src: "js/javascript-obfuscator/gauntlet-source.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/gauntlet",
        obf: "js/jsconfuser/gauntlet-obfuscated.js",
        src: "js/jsconfuser/gauntlet-source.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/string-conceal",
        obf: "js/jsconfuser/recovery/obf_checksum.stringconceal.js",
        src: "js/jsconfuser/recovery/src_checksum.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/string-compression",
        obf: "js/jsconfuser/recovery/obf_stringcompression.real.js",
        src: "js/jsconfuser/recovery/src_stringcompression.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/rgf-eval",
        obf: "js/jsconfuser/recovery/obf_tokenizer.rgf.js",
        src: "js/jsconfuser/recovery/src_tokenizer.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/statesum-real",
        obf: "js/jsconfuser/recovery/obf_statesum.real.js",
        src: "js/jsconfuser/recovery/src_statesum.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/statesum-spec",
        obf: "js/jsconfuser/recovery/obf_statesum.spec.js",
        src: "js/jsconfuser/recovery/src_statesum.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/deadcode",
        obf: "js/jsconfuser/recovery/obf_deadcode.real.js",
        src: "js/jsconfuser/recovery/src_deadcode.js",
        argv_battery: CLASSIFY_BATTERY,
    },
    Sample {
        name: "jsconfuser/deadcode-cff",
        obf: "js/jsconfuser/recovery/obf_deadcode_cff.real.js",
        src: "js/jsconfuser/recovery/src_deadcode.js",
        argv_battery: CLASSIFY_BATTERY,
    },
    Sample {
        name: "jsconfuser/integrity",
        obf: "js/jsconfuser/recovery/obf_integrity.real.js",
        src: "js/jsconfuser/recovery/src_integrity.js",
        argv_battery: INTEGRITY_BATTERY,
    },
    Sample {
        name: "jsconfuser/statesum-runtime",
        obf: "js/jsconfuser/recovery/obf_statesum_runtime.real.js",
        src: "js/jsconfuser/recovery/src_statesum_runtime.js",
        argv_battery: RUNTIME_BATTERY,
    },
    Sample {
        name: "jsconfuser/statesum-branch",
        obf: "js/jsconfuser/recovery/obf_statesum_branch.real.js",
        src: "js/jsconfuser/recovery/src_statesum_branch.js",
        argv_battery: CLASSIFY_BATTERY,
    },
    Sample {
        name: "jsconfuser/statesum-strings",
        obf: "js/jsconfuser/recovery/obf_statesum_strings.real.js",
        src: "js/jsconfuser/recovery/src_statesum_strings.js",
        argv_battery: STRINGS_BATTERY,
    },
    Sample {
        name: "jsconfuser/statesum-loop",
        obf: "js/jsconfuser/recovery/obf_statesum_loop.real.js",
        src: "js/jsconfuser/recovery/src_statesum_loop.js",
        argv_battery: LOOP_BATTERY,
    },
    Sample {
        name: "javascript-obfuscator/browser-cff",
        obf: "js/javascript-obfuscator/browser/obf_cff.js",
        src: "js/javascript-obfuscator/browser/source.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "javascript-obfuscator/browser-base64",
        obf: "js/javascript-obfuscator/browser/obf_base64.js",
        src: "js/javascript-obfuscator/browser/source.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/hello",
        obf: "js/javascript-obfuscator/obfuscated.js",
        src: "js/javascript-obfuscator/hello.js",
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/preset/low",
        obf: "src/javascript/obfuscator-io-samples/presets/low.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/preset/medium",
        obf: "src/javascript/obfuscator-io-samples/presets/medium.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/booleans",
        obf: "src/javascript/obfuscator-io-samples/controls/booleans.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/compact",
        obf: "src/javascript/obfuscator-io-samples/controls/compact.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/controlFlowFlattening",
        obf: "src/javascript/obfuscator-io-samples/controls/controlFlowFlattening.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/deadCodeInjection",
        obf: "src/javascript/obfuscator-io-samples/controls/deadCodeInjection.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/debugProtection",
        obf: "src/javascript/obfuscator-io-samples/controls/debugProtection.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/identifiersHexadecimal",
        obf: "src/javascript/obfuscator-io-samples/controls/identifiersHexadecimal.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/identifiersMangled",
        obf: "src/javascript/obfuscator-io-samples/controls/identifiersMangled.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/numbersToExpressions",
        obf: "src/javascript/obfuscator-io-samples/controls/numbersToExpressions.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/objectTransform",
        obf: "src/javascript/obfuscator-io-samples/controls/objectTransform.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/renameProperties",
        obf: "src/javascript/obfuscator-io-samples/controls/renameProperties.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/selfDefending",
        obf: "src/javascript/obfuscator-io-samples/controls/selfDefending.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/splitStrings",
        obf: "src/javascript/obfuscator-io-samples/controls/splitStrings.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/stringArrayBase64",
        obf: "src/javascript/obfuscator-io-samples/controls/stringArrayBase64.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/stringArrayRc4",
        obf: "src/javascript/obfuscator-io-samples/controls/stringArrayRc4.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/stringArrayRotate",
        obf: "src/javascript/obfuscator-io-samples/controls/stringArrayRotate.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/stringArrayShuffle",
        obf: "src/javascript/obfuscator-io-samples/controls/stringArrayShuffle.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/unicodeEscape",
        obf: "src/javascript/obfuscator-io-samples/controls/unicodeEscape.js",
        src: HIGH_CLEAN,
        argv_battery: NO_ARGS,
    },
];

enum Outcome {
    Verified,
    Skipped(String),
    Diverged(String),
}

fn corpus_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(rel)
}

fn load(rel: &str) -> String {
    let path: PathBuf = corpus_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("failed to read fixture {}: {e}", path.display())
    })
}

fn recover_full(sample: &Sample, obf_src: &str) -> String {
    if sample.obf.starts_with("js/jsconfuser/") {
        let opts: DeobOptions = DeobOptions::all();
        deobfuscate_all(obf_src, &opts).source
    } else {
        let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
        obfuscator_io_deobfuscate(obf_src, &opts)
            .expect("obfuscator.io full pipeline must not error")
            .source
    }
}

fn eval_outcome_guarded(program: &str, argv: &[&str]) -> Option<EvalOutcome> {
    let owned_program: String = program.to_owned();
    let owned_argv: Vec<String> = argv.iter().map(|arg: &&str| (*arg).to_owned()).collect();
    let (tx, rx): (
        mpsc::Sender<Option<EvalOutcome>>,
        mpsc::Receiver<Option<EvalOutcome>>,
    ) = mpsc::channel();
    thread::spawn(move || {
        let argv_refs: Vec<&str> = owned_argv.iter().map(String::as_str).collect();
        let outcome: Option<EvalOutcome> = eval_outcome_with_argv(&owned_program, &argv_refs);
        let _ = tx.send(outcome);
    });
    rx.recv_timeout(EVAL_TIMEOUT).ok().flatten()
}

fn check_sample(sample: &Sample) -> Outcome {
    let obf_src: String = load(sample.obf);
    let clean_src: String = load(sample.src);
    let recovered: String = recover_full(sample, &obf_src);

    for argv in sample.argv_battery {
        let want: EvalOutcome = match eval_outcome_guarded(&clean_src, argv) {
            Some(outcome) => outcome,
            None => {
                return Outcome::Skipped(format!(
                    "{}: original clean source is not boa-evaluable for argv {argv:?} within {EVAL_TIMEOUT:?} (engine gap, not a recovery defect)",
                    sample.name
                ));
            }
        };
        let Some(got): Option<EvalOutcome> = eval_outcome_guarded(&recovered, argv) else {
            return Outcome::Diverged(format!(
                "{}: recovered source failed to evaluate under boa for argv {argv:?} within {EVAL_TIMEOUT:?}; recovery emitted non-runnable or non-terminating code:\n{recovered}",
                sample.name
            ));
        };
        if want != got {
            return Outcome::Diverged(format!(
                "{}: recovered behavior diverged from the clean source for argv {argv:?}\n--want--\n{want:?}\n--got--\n{got:?}\n--recovered--\n{recovered}",
                sample.name
            ));
        }
    }

    Outcome::Verified
}

#[test]
fn corpus_wide_differential_reexec() {
    let mut verified: Vec<&str> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut diverged: Vec<String> = Vec::new();

    for sample in SAMPLES {
        match check_sample(sample) {
            Outcome::Verified => verified.push(sample.name),
            Outcome::Skipped(reason) => skipped.push(reason),
            Outcome::Diverged(reason) => diverged.push(reason),
        }
    }

    eprintln!(
        "corpus differential re-exec: {} verified, {} skipped, {} diverged (of {} samples)",
        verified.len(),
        skipped.len(),
        diverged.len(),
        SAMPLES.len()
    );
    for name in &verified {
        eprintln!("  verified: {name}");
    }
    for reason in &skipped {
        eprintln!("  skipped:  {reason}");
    }

    assert!(
        diverged.is_empty(),
        "behavior divergences surfaced by corpus-wide differential re-execution:\n\n{}",
        diverged.join("\n\n")
    );
    assert!(
        verified.len() >= DIFFERENTIAL_FLOOR,
        "differential coverage regressed: {} samples verified < floor {DIFFERENTIAL_FLOOR}",
        verified.len()
    );
}

fn assert_sample_verified(name: &str) {
    let sample: &Sample = SAMPLES
        .iter()
        .find(|s: &&Sample| s.name == name)
        .unwrap_or_else(|| panic!("unknown sample {name}"));
    match check_sample(sample) {
        Outcome::Verified => {}
        Outcome::Skipped(reason) | Outcome::Diverged(reason) => panic!("{reason}"),
    }
}

#[test]
fn javascript_obfuscator_gauntlet_differential_reexec() {
    assert_sample_verified("javascript-obfuscator/gauntlet");
}

#[test]
fn jsconfuser_gauntlet_differential_reexec() {
    assert_sample_verified("jsconfuser/gauntlet");
}

const fn routes_to_jsconfuser_full(family: JsObfuscator) -> bool {
    matches!(family, JsObfuscator::JsConfuser)
}

#[test]
fn deadcode_and_integrity_detect_as_jsconfuser_and_route_through_full() {
    const CASES: &[&str] = &[
        "js/jsconfuser/recovery/obf_deadcode.real.js",
        "js/jsconfuser/recovery/obf_deadcode_cff.real.js",
        "js/jsconfuser/recovery/obf_integrity.real.js",
    ];
    for rel in CASES {
        let src: String = load(rel);
        let det: Detection = detect(src.as_bytes());
        assert_eq!(
            det.family,
            JsObfuscator::JsConfuser,
            "{rel} must classify as JSConfuser (was misdetected as Minified), else --full misroutes it to the obfuscator.io pipeline; markers={:?}",
            det.markers
        );
        assert!(
            routes_to_jsconfuser_full(det.family),
            "{rel} must route through the JSConfuser --full pipeline (deobfuscate_all), not obfuscator.io"
        );
    }
}

#[test]
fn obfuscator_io_pipeline_is_bounded_on_integrity_trap() {
    let src: String = load("js/jsconfuser/recovery/obf_integrity.real.js");
    let controls: BTreeSet<ObfuscatorIoControl> =
        ObfuscatorIoControl::ALL.iter().copied().collect();
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions {
        controls,
        max_passes: u32::MAX,
    };
    let out: ObfuscatorIoOutput = obfuscator_io_deobfuscate(&src, &opts)
        .expect("the obfuscator.io pipeline must not error on the integrity self-hash trap");
    assert!(
        out.passes_run <= OBFUSCATOR_IO_MAX_PASS_CEILING,
        "even under a hostile max_passes, the obfuscator.io pipeline must stay bounded by the pass ceiling {OBFUSCATOR_IO_MAX_PASS_CEILING}; ran {} passes",
        out.passes_run
    );
}

const BROWSER_SAMPLES: &[&str] = &[
    "javascript-obfuscator/browser-cff",
    "javascript-obfuscator/browser-base64",
];

#[test]
fn browser_host_samples_move_from_skipped_to_verified() {
    let mut moved: usize = 0;
    for name in BROWSER_SAMPLES {
        let sample: &Sample = SAMPLES
            .iter()
            .find(|s: &&Sample| s.name == *name)
            .unwrap_or_else(|| panic!("unknown browser sample {name}"));
        let clean_src: String = load(sample.src);

        let bare: Option<EvalOutcome> = eval_outcome_bare(&clean_src);
        assert!(
            !matches!(
                bare,
                Some(EvalOutcome {
                    terminal: Terminal::Completed,
                    ..
                })
            ),
            "{name}: the clean source reads browser globals absent from the bare boa preamble, so the pre-shim oracle would SKIP it; bare outcome was {bare:?}"
        );

        let hosted: EvalOutcome = eval_outcome(&clean_src).unwrap_or_else(|| {
            panic!("{name}: clean source must evaluate under the browser-host shim")
        });
        assert_eq!(
            hosted.terminal,
            Terminal::Completed,
            "{name}: the browser-host shim must let the clean source run to completion; got {hosted:?}"
        );

        match check_sample(sample) {
            Outcome::Verified => moved += 1,
            Outcome::Skipped(reason) | Outcome::Diverged(reason) => panic!("{name}: {reason}"),
        }
    }
    eprintln!("browser-host shim moved {moved} sample(s) from skipped to differential-verified");
    assert_eq!(
        moved,
        BROWSER_SAMPLES.len(),
        "every browser-targeted sample must move from skipped to differentially verified once the host shim is present"
    );
}
