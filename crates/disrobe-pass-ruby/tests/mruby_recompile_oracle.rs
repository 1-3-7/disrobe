#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::{MrubyDecompiled, analyze_bytes};
use ruby_toolchain::{
    MRBC, MRUBY, MRUBY_MEASURED_SERIES, ToolchainBanner, ToolchainRequirement,
    require_with_requirement,
};

const GRADED: &str = "the mrbc recompile and mruby output comparison over the breadth corpus";

const STRAIGHT_LINE_SET: &[&str] = &["arith", "strings", "coll", "klass", "advanced"];
const EQUIVALENT_SET: &[&str] = &[
    "arith", "strings", "coll", "klass", "control", "blocks", "advanced", "jumps",
];
const WITHHELD_SET: &[&str] = &["exceptions", "loopbreak", "kwargs", "ensurecase"];
const BREADTH_SET: &[&str] = &[
    "arith",
    "strings",
    "coll",
    "klass",
    "control",
    "blocks",
    "exceptions",
    "advanced",
    "jumps",
    "loopbreak",
    "kwargs",
    "ensurecase",
];

const EXPECTED_OPCODE_COUNTS: &[(&str, u32, u32)] = &[
    ("arith", 22, 22),
    ("strings", 19, 19),
    ("coll", 35, 35),
    ("klass", 39, 39),
    ("control", 37, 37),
    ("blocks", 30, 30),
    ("exceptions", 22, 27),
    ("advanced", 138, 138),
    ("jumps", 63, 63),
    ("loopbreak", 31, 35),
    ("kwargs", 30, 31),
    ("ensurecase", 29, 33),
];

const UNMODELED_REASONS: &[(&str, &str)] = &[
    (
        "JMP",
        "an unconditional jump inside an irep whose catch_count is nonzero (rescue/else/ensure), \
         or inside a while loop that also contains a JMPUW-based break; structurable() withholds \
         structuring for both shapes",
    ),
    (
        "JMPIF",
        "a conditional jump inside an irep whose catch_count is nonzero; rescue, else, and ensure \
         control flow is not structurally recovered",
    ),
    (
        "JMPNOT",
        "a conditional jump that guards a JMPUW-based break inside a native while or until loop; \
         the guarded break never reaches the dedicated BREAK opcode",
    ),
    (
        "JMPUW",
        "break with a value inside a native while or until loop compiles through JMPUW, not the \
         dedicated BREAK opcode; JMPUW also marks a rescue/ensure unwind edge, so a JMPUW is never \
         assumed to be a loop break",
    ),
    (
        "RAISEIF",
        "RaiseIf only lowers when its condition register is a proven reference to $!, the \
         reraise-if-unhandled path inside a rescue clause; any other operand shape is unproven",
    ),
    (
        "KEY_P",
        "tests whether an optional keyword argument was supplied so its default value can be \
         computed; the result has no Ruby-source expression outside parameter-list syntax, so \
         rendering it as a body-level branch would fabricate syntax the source never had",
    ),
];

fn corpus_path(name: &str, ext: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("ruby");
    path.push("mruby");
    path.push("breadth");
    path.push(format!("{name}.{ext}"));
    path
}

fn recover(name: &str) -> MrubyDecompiled {
    let bytes: Vec<u8> =
        std::fs::read(corpus_path(name, "mrb")).expect("committed breadth .mrb fixture present");
    assert_eq!(&bytes[..4], b"RITE", "fixture {name} is a real RITE binary");
    let analysis = analyze_bytes(&bytes, &format!("{name}.mrb")).expect("analyze real mrb");
    analysis.mruby.expect("mruby analysis present").decompiled
}

fn reconstructed_body(dec: &MrubyDecompiled) -> String {
    dec.source
        .split_once("# --- reconstructed source ---\n")
        .map_or_else(|| dec.source.clone(), |(_, body)| body.to_owned())
}

fn write_temp(name: &str, source: &str) -> (ScratchFile, PathBuf) {
    let purpose: String = format!("disrobe_mruby_recovered_{name}");
    let (scratch, file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&purpose, "rb").expect("create recovered source scratch file");
    drop(file);
    let path: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&path, source).expect("write recovered source");
    (scratch, path)
}

fn mrbc_recompiles(rb_path: &PathBuf) -> bool {
    let (scratch, file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_mruby_recompile_probe", "mrb")
            .expect("create mrbc output scratch file");
    drop(file);
    let out_path: PathBuf = scratch.path().to_path_buf();
    let ok: bool = Command::new("mrbc")
        .arg("-o")
        .arg(&out_path)
        .arg(rb_path)
        .output()
        .is_ok_and(|o| o.status.success());
    ok
}

fn mruby_stdout(rb_path: &PathBuf) -> Option<Vec<u8>> {
    let output = Command::new("mruby").arg(rb_path).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(output.stdout)
}

fn stdout_matches(want: Option<&[u8]>, have: Option<&[u8]>) -> bool {
    matches!((want, have), (Some(want), Some(have)) if want == have)
}

#[test]
fn breadth_corpus_opcode_coverage_is_measured_not_dropped() {
    assert_eq!(
        EXPECTED_OPCODE_COUNTS.len(),
        BREADTH_SET.len(),
        "every breadth fixture must carry an expected opcode count"
    );
    for name in BREADTH_SET {
        let dec: MrubyDecompiled = recover(name);
        assert!(
            dec.lifted_opcodes > 0,
            "{name}: lift produced no opcodes at all"
        );
        assert_eq!(
            dec.modeled_opcodes + dec.unmodeled_opcodes,
            dec.lifted_opcodes,
            "{name}: modeled + unmodeled must account for every lifted opcode"
        );
        let (_, expected_modeled, expected_total): (&str, u32, u32) = *EXPECTED_OPCODE_COUNTS
            .iter()
            .find(|(fixture, _, _)| fixture == name)
            .unwrap_or_else(|| panic!("{name}: no expected opcode count recorded"));
        assert_eq!(
            dec.lifted_opcodes, expected_total,
            "{name}: lifted opcode count moved from the measured baseline; re-derive the figure \
             rather than editing the expectation to match a regression"
        );
        assert_eq!(
            dec.modeled_opcodes, expected_modeled,
            "{name}: modeled opcode count moved from the measured baseline, got {:?} unmodeled",
            dec.unmodeled_mnemonics
        );
        let pct: u32 = dec.modeled_opcodes.saturating_mul(100) / dec.lifted_opcodes;
        println!(
            "[{name}] opcode fidelity {}/{} ({pct}%) unmodeled={:?}",
            dec.modeled_opcodes, dec.lifted_opcodes, dec.unmodeled_mnemonics
        );
    }
    let total_modeled: u32 = EXPECTED_OPCODE_COUNTS
        .iter()
        .map(|(_, modeled, _)| modeled)
        .sum();
    let total_lifted: u32 = EXPECTED_OPCODE_COUNTS
        .iter()
        .map(|(_, _, total)| total)
        .sum();
    println!(
        "breadth corpus aggregate: {total_modeled}/{total_lifted} modeled across {} fixtures",
        BREADTH_SET.len()
    );
}

#[test]
fn every_unmodeled_mnemonic_carries_a_reason_that_still_applies() {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for name in BREADTH_SET {
        let dec: MrubyDecompiled = recover(name);
        for mnemonic in &dec.unmodeled_mnemonics {
            seen.insert(mnemonic.clone());
            assert!(
                UNMODELED_REASONS.iter().any(|(m, _)| m == mnemonic),
                "{name}: {mnemonic} is unmodeled but carries no recorded reason"
            );
        }
    }
    for (mnemonic, _) in UNMODELED_REASONS {
        assert!(
            seen.contains(*mnemonic),
            "{mnemonic} has a recorded reason but no breadth fixture leaves it unmodeled any \
             more; the reason entry is stale and must be removed"
        );
    }
}

#[test]
fn straight_line_corpus_models_every_opcode() {
    for name in STRAIGHT_LINE_SET {
        let dec: MrubyDecompiled = recover(name);
        assert_eq!(
            dec.unmodeled_opcodes, 0,
            "{name}: straight-line program must have zero unmodeled opcodes, got {:?}",
            dec.unmodeled_mnemonics
        );
        assert_eq!(
            dec.modeled_opcodes, dec.lifted_opcodes,
            "{name}: every opcode in a straight-line program must be modeled"
        );
    }
}

#[test]
fn if_and_while_control_flow_is_structured() {
    let dec: MrubyDecompiled = recover("control");
    assert_eq!(
        dec.unmodeled_opcodes, 0,
        "if/while control flow must be structured, not marked; got unmodeled {:?}",
        dec.unmodeled_mnemonics
    );
    assert_eq!(
        dec.modeled_opcodes, dec.lifted_opcodes,
        "every opcode in the control-flow program must be modeled"
    );
    assert!(
        !dec.source.contains("# unmodeled"),
        "no jump opcode may survive as an unmodeled marker: {}",
        dec.source
    );
    let body: String = dec
        .source
        .split_once("# --- reconstructed source ---\n")
        .map_or_else(|| dec.source.clone(), |(_, b)| b.to_owned());
    assert!(
        body.contains("if ("),
        "recovered source must carry an if: {body}"
    );
    assert!(
        body.contains("else"),
        "recovered source must carry an else: {body}"
    );
    assert!(
        body.contains("while ("),
        "recovered source must carry a while loop: {body}"
    );
    assert!(
        body.contains("end"),
        "structured blocks must be closed: {body}"
    );
}

#[test]
fn rescue_control_flow_withholds_partial_reconstruction() {
    let dec: MrubyDecompiled = recover("exceptions");
    assert!(
        dec.unmodeled_opcodes > 0,
        "rescue/ensure control flow is not structured yet, so its jumps stay honest markers"
    );
    assert!(
        dec.unmodeled_mnemonics.iter().any(|m| m.starts_with("JMP")),
        "the unmodeled set must name the jump opcodes it could not structure, got {:?}",
        dec.unmodeled_mnemonics
    );
    assert!(
        dec.source.contains("# unmodeled"),
        "unmodeled opcodes must surface as visible markers in the recovered source"
    );
    assert!(
        !dec.has_body,
        "a protected IREP with unmodeled control flow must not be handed out as executable ruby"
    );
    let body: String = reconstructed_body(&dec);
    assert!(
        body.lines()
            .all(|line: &str| line.trim().is_empty() || line.trim_start().starts_with('#')),
        "withheld reconstruction must not contain executable ruby: {body}"
    );
}

#[test]
fn stdout_comparator_rejects_a_changed_real_mruby_program() {
    let mruby: Option<ToolchainBanner> = require_with_requirement(
        &MRUBY,
        Some(MRUBY_MEASURED_SERIES),
        GRADED,
        ToolchainRequirement::Mandatory,
    );
    assert!(mruby.is_some(), "the pinned mruby probe must succeed");

    let original_path: PathBuf = corpus_path("strings", "rb");
    let original: String =
        std::fs::read_to_string(&original_path).expect("read committed strings source fixture");
    let needle: &str = "name = \"world\"";
    assert_eq!(
        original.matches(needle).count(),
        1,
        "the output-bearing mutation target must occur exactly once"
    );
    let mutated: String = original.replacen(needle, "name = \"mutated\"", 1);
    let (_mutated_scratch, mutated_path): (ScratchFile, PathBuf) =
        write_temp("strings_mutated", &mutated);
    let want: Option<Vec<u8>> = mruby_stdout(&original_path);
    let have: Option<Vec<u8>> = mruby_stdout(&mutated_path);
    assert!(
        want.is_some() && have.is_some(),
        "both real mruby executions must succeed before grading"
    );
    assert!(
        !stdout_matches(want.as_deref(), have.as_deref()),
        "the exact stdout comparator accepted an output-bearing source mutation"
    );
}

#[test]
fn mrbc_recompile_and_semantic_equivalence_oracle() {
    let mrbc: Option<ToolchainBanner> = require_with_requirement(
        &MRBC,
        Some(MRUBY_MEASURED_SERIES),
        GRADED,
        ToolchainRequirement::Mandatory,
    );
    let mruby: Option<ToolchainBanner> = require_with_requirement(
        &MRUBY,
        Some(MRUBY_MEASURED_SERIES),
        GRADED,
        ToolchainRequirement::Mandatory,
    );
    assert!(
        mrbc.is_some() && mruby.is_some(),
        "the mandatory mrbc and mruby toolchain probes must both succeed"
    );

    let mut recompiled: u32 = 0;
    let mut equivalent: u32 = 0;
    let mut withheld: u32 = 0;
    let total: u32 = BREADTH_SET.len() as u32;

    for name in BREADTH_SET {
        let dec: MrubyDecompiled = recover(name);
        let expected_withheld: bool = WITHHELD_SET.contains(name);
        assert_eq!(
            !dec.has_body, expected_withheld,
            "{name}: source eligibility must match the explicit withheld set"
        );
        if !dec.has_body {
            withheld += 1;
            println!("[{name}] source withheld");
            continue;
        }
        let body: String = reconstructed_body(&dec);
        let (_recovered_scratch, recovered_path): (ScratchFile, PathBuf) = write_temp(name, &body);
        let original_path: PathBuf = corpus_path(name, "rb");

        let recompiles: bool = mrbc_recompiles(&recovered_path);
        if recompiles {
            recompiled += 1;
        }

        let want: Option<Vec<u8>> = mruby_stdout(&original_path);
        let have: Option<Vec<u8>> = mruby_stdout(&recovered_path);
        let same: bool = stdout_matches(want.as_deref(), have.as_deref());
        if same {
            equivalent += 1;
        }
        println!(
            "[{name}] recompile={recompiles} semantic_equivalent={same} want={want:?} have={have:?}"
        );
    }

    println!(
        "mruby oracle: recompiled {recompiled}/{total}, semantically equivalent {equivalent}/{total}, source withheld {withheld}/{total}"
    );

    for name in EQUIVALENT_SET {
        let dec: MrubyDecompiled = recover(name);
        let body: String = reconstructed_body(&dec);
        let (_recovered_scratch, recovered_path): (ScratchFile, PathBuf) = write_temp(name, &body);
        let original_path: PathBuf = corpus_path(name, "rb");

        assert!(
            mrbc_recompiles(&recovered_path),
            "{name}: mrbc must recompile the recovered source"
        );
        let want: Option<Vec<u8>> = mruby_stdout(&original_path);
        let have: Option<Vec<u8>> = mruby_stdout(&recovered_path);
        assert!(
            stdout_matches(want.as_deref(), have.as_deref()),
            "{name}: recovered source must produce identical mruby output to the original; want={want:?} have={have:?}"
        );
    }

    assert_eq!(
        withheld,
        u32::try_from(WITHHELD_SET.len()).expect("withheld set length fits u32"),
        "the explicit unsafe-source fixtures must remain withheld instead of emitting partial ruby"
    );
    let eligible: u32 = total.saturating_sub(withheld);
    assert_eq!(
        recompiled, eligible,
        "every source-eligible recovered program must be mrbc-recompilable, got {recompiled}/{eligible}"
    );
    assert_eq!(
        equivalent, eligible,
        "every source-eligible recovered program must produce the original mruby output, got {equivalent}/{eligible}"
    );
}
