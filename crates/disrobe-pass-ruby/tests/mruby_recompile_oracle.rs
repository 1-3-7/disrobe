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
const EQUIVALENT_SET: &[&str] = &["strings", "coll", "klass", "control", "blocks", "advanced"];
const WITHHELD_SET: &[&str] = &["arith", "exceptions"];
const BREADTH_SET: &[&str] = &[
    "arith",
    "strings",
    "coll",
    "klass",
    "control",
    "blocks",
    "exceptions",
    "advanced",
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
        let pct: u32 = dec.modeled_opcodes.saturating_mul(100) / dec.lifted_opcodes;
        println!(
            "[{name}] opcode fidelity {}/{} ({pct}%) unmodeled={:?}",
            dec.modeled_opcodes, dec.lifted_opcodes, dec.unmodeled_mnemonics
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
