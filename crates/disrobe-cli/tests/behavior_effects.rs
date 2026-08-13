#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

fn fixture(relative: &str) -> PathBuf {
    let path: PathBuf = workspace_root().join("corpus").join(relative);
    assert!(
        path.is_file(),
        "this case reports effects for a committed module, so its absence is a damaged checkout: {}",
        path.display()
    );
    path
}

fn behavior_json(relative: &str, effects: bool) -> serde_json::Value {
    let bin: PathBuf = cargo_bin();
    let mut command: Command = Command::new(&bin);
    command.arg("behavior").arg(fixture(relative)).arg("--json");
    if effects {
        command.arg("--effects");
    }
    let output: Output = command
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", bin.display()));
    assert!(
        output.status.success(),
        "behavior {relative} exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "behavior {relative} must emit json: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn sum_of(value: &serde_json::Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
        .values()
        .map(|count: &serde_json::Value| count.as_u64().expect("a count"))
        .sum()
}

#[test]
fn the_effect_table_is_reached_only_when_the_flag_asks_for_it() {
    let without: serde_json::Value = behavior_json("beam/disasm_oracle/probe.beam", false);
    assert!(
        without.get("effects").is_none(),
        "behavior without --effects must keep its existing document shape, got {without:#?}"
    );
    let with: serde_json::Value = behavior_json("beam/disasm_oracle/probe.beam", true);
    assert!(
        with.get("effects").is_some(),
        "behavior --effects must carry the effect table, got {with:#?}"
    );
    assert_eq!(
        without.get("categories"),
        with.get("categories"),
        "asking for effects must not change what behaviors are reported"
    );
}

#[test]
fn every_counted_effect_carries_exactly_one_piece_of_evidence() {
    for relative in [
        "beam/disasm_oracle/probe.beam",
        "beam/disasm_oracle/probe2.beam",
    ] {
        let report: serde_json::Value = behavior_json(relative, true);
        let effects: &serde_json::Value = report.get("effects").expect("effects");

        let instructions: u64 = effects
            .get("instructions")
            .and_then(serde_json::Value::as_u64)
            .expect("instructions");
        let functions: u64 = effects
            .get("functions")
            .and_then(serde_json::Value::as_u64)
            .expect("functions");
        assert!(
            instructions > 0 && functions > 0,
            "{relative} is a real module, so it must lift to instructions and functions"
        );

        let effect_free: u64 = effects
            .get("effect_free")
            .and_then(serde_json::Value::as_u64)
            .expect("effect_free");
        let unknown: u64 = effects
            .get("unknown")
            .and_then(serde_json::Value::as_u64)
            .expect("unknown");
        assert!(
            effect_free.saturating_add(unknown) <= instructions,
            "{relative} cannot have more effect-free and unmodelled rows than it has instructions"
        );

        let by_effect: u64 = sum_of(effects, "effects");
        let by_evidence: u64 = sum_of(effects, "provenance");
        assert!(
            by_effect > 0,
            "{relative} lifts to instructions, so at least one of them must carry a hard effect"
        );
        assert_eq!(
            by_effect, by_evidence,
            "{relative} counted {by_effect} effect occurrence(s) but {by_evidence} piece(s) of \
             evidence; every occurrence is assigned by exactly one source, so these must agree"
        );
    }
}

#[test]
fn two_different_modules_do_not_report_the_same_effect_table() {
    let first: serde_json::Value = behavior_json("beam/disasm_oracle/probe.beam", true);
    let second: serde_json::Value = behavior_json("beam/disasm_oracle/probe2.beam", true);
    assert_ne!(
        first.get("effects"),
        second.get("effects"),
        "two modules of different sizes must not produce an identical effect table, or the table \
         is not being derived from the module at all"
    );
}

#[test]
fn an_input_the_lifter_does_not_accept_is_refused_rather_than_reported_empty() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-behavior-effects")
            .expect("create scratch directory");
    let path: PathBuf = scratch.path().join("not-a-module.bin");
    std::fs::write(&path, [0x00_u8; 64]).expect("write the input");

    let bin: PathBuf = cargo_bin();
    let output: Output = Command::new(&bin)
        .arg("behavior")
        .arg(&path)
        .arg("--effects")
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", bin.display()));
    assert!(
        !output.status.success(),
        "an input that does not lift must be refused, not reported as having no effects"
    );
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DR-"),
        "the refusal must carry a typed error code, got {stderr}"
    );
}
