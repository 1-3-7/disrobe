#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;
use std::process::Command;

use common::{Run, cli_binary, run_disrobe, temp_dir};

fn write_config(dir: &std::path::Path, body: &str) -> PathBuf {
    let path: PathBuf = dir.join(".disrobe.toml");
    std::fs::write(&path, body).expect("write .disrobe.toml");
    path
}

#[test]
fn a_removed_determinism_seed_is_refused_on_both_surfaces() {
    let rejected: Run = run_disrobe(&["--seed", "42", "config", "show"]);
    assert_ne!(
        rejected.code, 0,
        "a script still passing --seed must fail visibly rather than run with different behaviour"
    );

    let dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cfg-seed-removed");
    let dir: PathBuf = dir_scratch.path().to_path_buf();
    let path: PathBuf = write_config(&dir, "[execution]\nseed = 42\n");
    let stale: Run = run_disrobe(&["config", "show", "--config", path.to_str().unwrap()]);
    assert_ne!(
        stale.code, 0,
        "an existing .disrobe.toml carrying execution.seed must fail to parse, not be ignored"
    );

    let clean: Run = run_disrobe(&["config", "show"]);
    assert_eq!(
        clean.code, 0,
        "config show must still succeed: {}",
        clean.stderr
    );
    assert!(
        !clean.stdout.contains("seed"),
        "config show must not print a key the binary no longer reads; got: {}",
        clean.stdout
    );
}

#[test]
fn every_global_flag_the_binary_parses_reaches_a_consumer() {
    let source: &str = include_str!("../src/cli/config_merge.rs");
    let declared: Vec<String> = source
        .match_indices("Arg::new(\"")
        .filter_map(|(at, needle): (usize, &str)| {
            source
                .get(at + needle.len()..)
                .and_then(|rest: &str| rest.split('"').next())
                .map(str::to_owned)
        })
        .collect();
    assert!(
        declared.len() >= 8,
        "the global flag table declares only {} flag(s), so this check is reading the wrong shape \
         and would pass over an orphan it cannot see: {declared:?}",
        declared.len()
    );
    let effective: &str = source
        .split("pub(crate) struct EffectiveGlobals {")
        .nth(1)
        .and_then(|tail: &str| tail.split('}').next())
        .expect("EffectiveGlobals must be declared");
    let orphans: Vec<&String> = declared
        .iter()
        .filter(|name: &&String| !effective.contains(name.as_str()))
        .collect();
    assert!(
        orphans.is_empty(),
        "these global flags are parsed and merged but reach no consumer, so they document \
         behaviour the binary does not have: {orphans:?}"
    );
}

#[test]
fn config_show_reports_builtin_defaults_without_file() {
    let dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cfg-defaults");
    let dir: PathBuf = dir_scratch.path().to_path_buf();
    let bogus: PathBuf = dir.join("does-not-exist.toml");
    let r: Run = run_disrobe(&["config", "show", "--config", bogus.to_str().unwrap()]);
    assert_ne!(r.code, 0, "missing explicit --config must fail fast");
    assert!(
        r.stderr.contains("DR-CLI-0332"),
        "expected DR-CLI-0332; stderr={}",
        r.stderr
    );
}

#[test]
fn config_show_json_reflects_explicit_file() {
    let dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cfg-explicit");
    let dir: PathBuf = dir_scratch.path().to_path_buf();
    let cfg: PathBuf = write_config(
        &dir,
        "[output]\njson = true\n[execution]\nthreads = 5\nmax_depth = 12\n",
    );
    let r: Run = run_disrobe(&[
        "--json",
        "config",
        "show",
        "--config",
        cfg.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "config show must succeed; stderr={}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("config show --json must emit valid json");
    assert_eq!(parsed["config"]["output"]["json"], serde_json::json!(true));
    assert_eq!(
        parsed["config"]["execution"]["threads"],
        serde_json::json!(5)
    );
    assert_eq!(
        parsed["config"]["execution"]["max_depth"],
        serde_json::json!(12)
    );
}

#[test]
fn malformed_config_fails_fast() {
    let dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cfg-malformed");
    let dir: PathBuf = dir_scratch.path().to_path_buf();
    let cfg: PathBuf = write_config(&dir, "[output]\nthis is not = = valid toml\n");
    let r: Run = run_disrobe(&["config", "show", "--config", cfg.to_str().unwrap()]);
    assert_ne!(r.code, 0, "malformed toml must fail");
    assert!(
        r.stderr.contains("DR-CLI-0330"),
        "expected DR-CLI-0330; stderr={}",
        r.stderr
    );
}

#[test]
fn unknown_key_in_config_is_rejected() {
    let dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cfg-unknown");
    let dir: PathBuf = dir_scratch.path().to_path_buf();
    let cfg: PathBuf = write_config(&dir, "[output]\nnot_a_real_key = 1\n");
    let r: Run = run_disrobe(&["config", "show", "--config", cfg.to_str().unwrap()]);
    assert_ne!(r.code, 0, "unknown key must fail");
    assert!(
        r.stderr.contains("DR-CLI-0330"),
        "expected DR-CLI-0330; stderr={}",
        r.stderr
    );
}

#[test]
fn config_drives_json_output_for_unrelated_command() {
    let dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cfg-drives-json");
    let dir: PathBuf = dir_scratch.path().to_path_buf();
    let cfg: PathBuf = write_config(&dir, "[output]\njson = true\n");
    let r: Run = run_disrobe(&["config", "show", "--config", cfg.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    assert!(
        r.stdout.trim_start().starts_with('{'),
        "config json=true must make output JSON without --json; got: {}",
        r.stdout
    );
}

#[test]
fn config_init_writes_template_and_round_trips() {
    let dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cfg-init");
    let dir: PathBuf = dir_scratch.path().to_path_buf();
    let target: PathBuf = dir.join("generated.toml");
    let r: Run = run_disrobe(&["config", "init", "--out", target.to_str().unwrap()]);
    assert_eq!(r.code, 0, "config init must succeed; stderr={}", r.stderr);
    assert!(target.is_file(), "template must be written");
    let show: Run = run_disrobe(&[
        "--json",
        "config",
        "show",
        "--config",
        target.to_str().unwrap(),
    ]);
    assert_eq!(
        show.code, 0,
        "the generated template must parse cleanly; stderr={}",
        show.stderr
    );
}

#[test]
fn config_auto_discovers_walking_up_from_cwd() {
    let root_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cfg-discover");
    let root: PathBuf = root_scratch.path().to_path_buf();
    write_config(&root, "[output]\njson = true\n");
    let nested: PathBuf = root.join("a").join("b");
    std::fs::create_dir_all(&nested).expect("mk nested");
    let bin: PathBuf = cli_binary();
    let output: std::process::Output = Command::new(&bin)
        .current_dir(&nested)
        .args(["config", "show"])
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    assert!(
        output.status.success(),
        "config show must succeed in nested dir"
    );
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        stdout.trim_start().starts_with('{'),
        "auto-discovered config json=true should make output JSON; got: {stdout}"
    );
    assert!(
        stdout.contains(".disrobe.toml"),
        "resolved source should reference the discovered file; got: {stdout}"
    );
}
