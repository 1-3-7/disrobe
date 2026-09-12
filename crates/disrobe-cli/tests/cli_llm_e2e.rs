#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::same_item_push
)]

use std::path::PathBuf;
use std::process::Command;

use jsonschema::Validator;
use serde_json::Value as Json;

fn cli_binary() -> PathBuf {
    let mut p: PathBuf = env_target_dir();
    p.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    p
}

fn env_target_dir() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn temp_path(stem: &str, ext: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let purpose: String = format!("disrobe-llm-e2e-{stem}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let path: PathBuf = scratch.path().join(format!("payload.{ext}"));
    (scratch, path)
}

const REAL_PYC: &str =
    "corpus/python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc";

const REAL_ELF: &str = "corpus/native/discovery/disc.unstripped.elf";

const REAL_CLASSFILE: &str = "corpus/jvm/allatori/AllatoriCaller.class";

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn write_decodable_pyc(path: &PathBuf) {
    let source: PathBuf = workspace_root().join(REAL_PYC);
    assert!(
        source.is_file(),
        "{REAL_PYC} is tracked in git and every case here decompiles it, so its absence is a \
         damaged checkout rather than an optional dependency: {}",
        source.display()
    );
    std::fs::copy(&source, path).expect("stage the committed pyc");
}

fn run_disrobe(args: &[&str]) -> (i32, String, String) {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} - run `cargo build -p disrobe-cli`",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn schema_root() -> Json {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("schemas");
    p.push("disrobe-metadata-llm-v1.json");
    let bytes: Vec<u8> =
        std::fs::read(&p).unwrap_or_else(|e| panic!("read schema {}: {e}", p.display()));
    serde_json::from_slice(&bytes).expect("schema parse")
}

fn tracked_fixture(relative: &str) -> PathBuf {
    let source: PathBuf = workspace_root().join(relative);
    assert!(
        source.is_file(),
        "{relative} is tracked in git and this case reads it, so its absence is a damaged \
         checkout rather than an optional dependency: {}",
        source.display()
    );
    source
}

fn bundle_for(args: &[&str], stem: &str) -> (disrobe_core::scratch::ScratchDir, Json) {
    let (scratch, bundle_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path(stem, "json");
    let bundle_str: String = bundle_out.to_string_lossy().into_owned();
    let mut full: Vec<&str> = vec!["--metadata-out", &bundle_str, "--force"];
    full.extend_from_slice(args);
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&full);
    assert_eq!(
        code, 0,
        "the run this case grades must succeed, or the bundle it inspects never exists and the \
         case reports success while checking nothing:\nargs={full:?}\nstdout=\n{stdout}\n\
         stderr=\n{stderr}"
    );
    let bytes: Vec<u8> = std::fs::read(&bundle_out).unwrap_or_else(|e| {
        panic!(
            "the run was asked to write {} and this case reads it: {e}\nstdout=\n{stdout}\n\
             stderr=\n{stderr}",
            bundle_out.display()
        )
    });
    let bundle: Json = serde_json::from_slice(&bytes).expect("parse bundle");
    let schema: Json = schema_root();
    let validator: Validator = jsonschema::validator_for(&schema).expect("compile");
    let errors: Vec<String> = validator
        .iter_errors(&bundle)
        .map(|e: jsonschema::ValidationError<'_>| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "an emitted category that the published schema rejects is a broken promise to every \
         consumer of the bundle:\n{}",
        errors.join("\n")
    );
    (scratch, bundle)
}

fn entries(bundle: &Json, category: &str) -> Vec<Json> {
    bundle
        .get("categories")
        .and_then(|c: &Json| c.get(category))
        .and_then(|c: &Json| c.get("entries"))
        .and_then(Json::as_array)
        .unwrap_or_else(|| panic!("category `{category}` present in the bundle"))
        .clone()
}

fn applicable_value(bundle: &Json, category: &str) -> Json {
    let found: Vec<Json> = entries(bundle, category)
        .into_iter()
        .filter(|e: &Json| e.get("applicable").and_then(Json::as_bool) == Some(true))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one pass answers for `{category}`; got {}",
        serde_json::to_string_pretty(&entries(bundle, category)).unwrap()
    );
    found
        .into_iter()
        .next()
        .and_then(|e: Json| e.get("value").cloned())
        .expect("an applicable envelope carries a value")
}

fn array_len(value: &Json, field: &str) -> usize {
    value
        .get(field)
        .and_then(Json::as_array)
        .unwrap_or_else(|| panic!("`{field}` array present in {value}"))
        .len()
}

#[test]
fn cfg_and_dfg_are_emitted_for_a_native_binary() {
    let elf: PathBuf = tracked_fixture(REAL_ELF);
    let elf_str: String = elf.to_string_lossy().into_owned();
    let (_scratch, bundle): (disrobe_core::scratch::ScratchDir, Json) =
        bundle_for(&["--cfg", "--dfg", "taint", &elf_str], "native-cfg");

    let cfg: Json = applicable_value(&bundle, "cfg");
    assert!(
        array_len(&cfg, "functions") > 0,
        "a disassemblable native binary has functions: {cfg}"
    );
    assert!(
        array_len(&cfg, "edges") > 0,
        "a native binary with branching control flow has cfg edges: {cfg}"
    );
    assert_eq!(
        cfg.get("lang").and_then(Json::as_str),
        Some("native-x86"),
        "the summary records which lifter produced the module"
    );

    let dfg: Json = applicable_value(&bundle, "dfg");
    assert!(
        array_len(&dfg, "defs") > 0,
        "a native binary that writes memory has definition sites: {dfg}"
    );
    assert!(
        array_len(&dfg, "uses") > 0,
        "at least one memory write reaches a later read, which is one def-use edge: {dfg}"
    );
}

#[test]
fn a_non_native_source_lang_reaches_the_cfg() {
    let classfile: PathBuf = tracked_fixture(REAL_CLASSFILE);
    let class_str: String = classfile.to_string_lossy().into_owned();
    let (_scratch, bundle): (disrobe_core::scratch::ScratchDir, Json) =
        bundle_for(&["--cfg", "taint", &class_str], "jvm-cfg");

    let cfg: Json = applicable_value(&bundle, "cfg");
    assert_eq!(
        cfg.get("lang").and_then(Json::as_str),
        Some("jvm"),
        "the route is not x86-only; a bytecode lifter reaches the same summary: {cfg}"
    );
    assert!(array_len(&cfg, "functions") > 0);
    assert!(array_len(&cfg, "edges") > 0);
}

#[test]
fn pack_2_and_pack_3_carry_the_cfg_and_dfg_their_help_text_claims() {
    let elf: PathBuf = tracked_fixture(REAL_ELF);
    let elf_str: String = elf.to_string_lossy().into_owned();

    let (_pack2_scratch, pack2): (disrobe_core::scratch::ScratchDir, Json) =
        bundle_for(&["--metadata-pack-2", "taint", &elf_str], "pack2-cfg");
    assert!(array_len(&applicable_value(&pack2, "cfg"), "functions") > 0);

    let (_pack3_scratch, pack3): (disrobe_core::scratch::ScratchDir, Json) =
        bundle_for(&["--metadata-pack-3", "taint", &elf_str], "pack3-dfg");
    assert!(array_len(&applicable_value(&pack3, "cfg"), "functions") > 0);
    assert!(array_len(&applicable_value(&pack3, "dfg"), "defs") > 0);
}

#[test]
fn an_input_that_never_reaches_mir_reports_unavailable_rather_than_empty() {
    let (_scratch, script): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("unreachable", "py");
    std::fs::write(&script, b"import base64\nx = base64.b64decode('aGk=')\n")
        .expect("stage a plain python script");
    let (_out_scratch, out_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("unreachable-out", "py");
    let script_str: String = script.to_string_lossy().into_owned();
    let out_str: String = out_path.to_string_lossy().into_owned();

    let (_bundle_scratch, bundle): (disrobe_core::scratch::ScratchDir, Json) = bundle_for(
        &[
            "--cfg",
            "--dfg",
            "py",
            "deob",
            &script_str,
            "--out",
            &out_str,
        ],
        "unreachable-bundle",
    );

    for category in ["cfg", "dfg"] {
        let found: Vec<Json> = entries(&bundle, category)
            .into_iter()
            .filter(|e: &Json| e.get("pass").and_then(Json::as_str) == Some("disrobe-irsummary"))
            .collect();
        assert_eq!(
            found.len(),
            1,
            "the summarizer reports for `{category}` even when it cannot answer, or a consumer \
             cannot tell an unreachable input from a category nobody was asked about"
        );
        let envelope: &Json = &found[0];
        assert_eq!(
            envelope.get("applicable").and_then(Json::as_bool),
            Some(false),
            "a plain python script never reaches the Mir rung"
        );
        assert!(
            envelope.get("value").is_none_or(Json::is_null),
            "an unavailable category carries no value, which is what separates it from an empty \
             one: {envelope}"
        );
        let reason: &str = envelope
            .get("reason")
            .and_then(Json::as_str)
            .expect("an unavailable category states why");
        assert!(
            reason.contains("Mir rung"),
            "the reason names the rung the input failed to reach: {reason}"
        );
    }
}

#[test]
fn a_selection_without_cfg_or_dfg_records_no_ir_summary_pass() {
    let (_pyc_scratch, pyc): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("pack1", "pyc");
    write_decodable_pyc(&pyc);
    let (_out_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("pack1-out", "dir");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();

    let (_bundle_scratch, bundle): (disrobe_core::scratch::ScratchDir, Json) = bundle_for(
        &[
            "--metadata-pack-1",
            "py",
            "disasm",
            &pyc_str,
            "--out",
            &out_str,
        ],
        "pack1-bundle",
    );

    let passes: Vec<&str> = bundle
        .get("pipeline")
        .and_then(Json::as_array)
        .expect("pipeline array")
        .iter()
        .filter_map(|s: &Json| s.get("pass").and_then(Json::as_str))
        .collect();
    assert!(
        !passes.contains(&"disrobe-irsummary"),
        "pack-1 names neither cfg nor dfg, so the bundle must be exactly what it was before the \
         summarizer was wired: {passes:?}"
    );
    assert!(
        bundle
            .get("categories")
            .and_then(|c: &Json| c.get("cfg"))
            .is_none(),
        "pack-1 does not select cfg"
    );
}

#[test]
fn llm_flag_help_lists_metadata_options() {
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&["--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("--llm"), "help missing --llm:\n{stdout}");
    assert!(stdout.contains("--metadata-pack-1"));
    assert!(stdout.contains("--metadata-format"));
}

#[test]
fn unknown_metadata_format_errors_with_dr_cli_0440() {
    let (code, _stdout, stderr): (i32, String, String) = run_disrobe(&[
        "--llm",
        "--metadata-format",
        "xml",
        "py",
        "decompile",
        "/nonexistent",
    ]);
    assert_ne!(code, 0, "must error");
    assert!(
        stderr.contains("DR-CLI-0440") || stderr.contains("--metadata-format"),
        "expected DR-CLI-0440, stderr={stderr}"
    );
}

#[test]
fn decryption_keys_without_auth_errors_with_dr_cli_0420() {
    let (code, _stdout, stderr): (i32, String, String) =
        run_disrobe(&["--decryption-keys", "py", "decompile", "/nonexistent"]);
    assert_ne!(code, 0, "must error");
    assert!(
        stderr.contains("DR-CLI-0420") || stderr.contains("decryption-keys"),
        "expected DR-CLI-0420, stderr={stderr}"
    );
}

#[test]
fn no_llm_flags_writes_no_bundle() {
    let (_pyc_scratch, pyc): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("noflag", "pyc");
    write_decodable_pyc(&pyc);
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("noflag-out", "dir");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let (code, stdout, stderr): (i32, String, String) =
        run_disrobe(&["py", "decompile", &pyc_str, "--out", &out_str]);
    assert_eq!(
        code, 0,
        "the run must succeed, or this case proves nothing about what a successful run writes \
         without the flags:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let bundle_path: PathBuf = out_dir.join("py-decompile.disrobe.llm.json");
    assert!(
        !bundle_path.exists(),
        "must not write a bundle without --llm"
    );
}

#[test]
fn llm_briefs_writes_agents_and_skill_markdown() {
    let (_pyc_scratch, pyc): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("briefs", "pyc");
    write_decodable_pyc(&pyc);
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("briefs-out", "dir");
    let (_bundle_out_scratch, bundle_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("briefs-bundle", "json");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let bundle_str: String = bundle_out.to_string_lossy().into_owned();

    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "--llm-briefs",
        "--metadata-out",
        &bundle_str,
        "--force",
        "py",
        "decompile",
        &pyc_str,
        "--out",
        &out_str,
    ]);
    assert_eq!(
        code, 0,
        "the run this case grades must succeed, or the bundle it inspects never exists and the \
         case reports success while checking nothing:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        bundle_out.exists(),
        "the run was asked to write {} and this case reads it, so a missing bundle is the defect \
         this case exists to catch:\nstdout=\n{stdout}\nstderr=\n{stderr}",
        bundle_out.display()
    );

    let bundle_dir: &std::path::Path = bundle_out.parent().expect("bundle parent");
    let agents_path: PathBuf = bundle_dir.join("AGENTS.md");
    let skill_path: PathBuf = bundle_dir.join("SKILL.md");

    assert!(agents_path.exists(), "AGENTS.md not written");
    assert!(skill_path.exists(), "SKILL.md not written");

    let agents: String = std::fs::read_to_string(&agents_path).expect("read AGENTS.md");
    let skill: String = std::fs::read_to_string(&skill_path).expect("read SKILL.md");

    assert!(!agents.trim().is_empty(), "AGENTS.md is empty");
    assert!(!skill.trim().is_empty(), "SKILL.md is empty");

    assert!(
        agents.starts_with("# AGENTS.md"),
        "AGENTS.md missing header"
    );
    assert!(
        agents.contains("## Artifact"),
        "AGENTS.md missing artifact section"
    );
    assert!(
        agents.contains("disrobe.metadata.llm.v1"),
        "AGENTS.md missing schema reference"
    );

    assert!(skill.starts_with("---\n"), "SKILL.md missing frontmatter");
    assert!(
        skill.contains("name: reconstruct-"),
        "SKILL.md missing skill name"
    );
    assert!(
        skill.contains("## Reconstruction procedure"),
        "SKILL.md missing procedure"
    );

    let rerun: String = std::fs::read_to_string(&agents_path).expect("reread AGENTS.md");
    assert_eq!(agents, rerun, "AGENTS.md must be stable");
}

#[test]
fn llm_flag_writes_schema_conforming_bundle() {
    let (_pyc_scratch, pyc): (disrobe_core::scratch::ScratchDir, PathBuf) = temp_path("llm", "pyc");
    write_decodable_pyc(&pyc);
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("llm-out", "dir");
    let (_bundle_out_scratch, bundle_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("llm-bundle", "json");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let bundle_str: String = bundle_out.to_string_lossy().into_owned();

    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "--llm",
        "--i-have-authorization",
        "--metadata-out",
        &bundle_str,
        "--force",
        "py",
        "decompile",
        &pyc_str,
        "--out",
        &out_str,
    ]);
    assert_eq!(
        code, 0,
        "the run this case grades must succeed, or the bundle it inspects never exists and the \
         case reports success while checking nothing:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        bundle_out.exists(),
        "the run was asked to write {} and this case reads it, so a missing bundle is the defect \
         this case exists to catch:\nstdout=\n{stdout}\nstderr=\n{stderr}",
        bundle_out.display()
    );
    let bytes: Vec<u8> = std::fs::read(&bundle_out).expect("read bundle");
    let bundle: Json = serde_json::from_slice(&bytes).expect("parse bundle");
    assert_eq!(
        bundle.get("schema").and_then(Json::as_str),
        Some("disrobe.metadata.llm.v1")
    );
    let schema: Json = schema_root();
    let validator: Validator = jsonschema::validator_for(&schema).expect("compile");
    let errors: Vec<String> = validator
        .iter_errors(&bundle)
        .map(|e: jsonschema::ValidationError<'_>| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "bundle failed schema:\n{}\nbundle={}",
        errors.join("\n"),
        serde_json::to_string_pretty(&bundle).unwrap()
    );
}
