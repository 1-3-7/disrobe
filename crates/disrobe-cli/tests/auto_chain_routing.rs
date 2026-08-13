#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::chain::{DetectContext, DetectVerdict, DetectorPick, PassRegistry};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
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

#[allow(clippy::disallowed_methods)]
fn tmp_out(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-routing-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn run_auto(input: &Path, out: &Path) -> Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {}; run `cargo build -p disrobe-cli` first",
        bin.display()
    );
    Command::new(&bin)
        .arg("auto")
        .arg(input)
        .arg("--out")
        .arg(out)
        .output()
        .expect("auto must run")
}

fn chain_of(out: &Path) -> serde_json::Value {
    let path: PathBuf = out.join("chain.json");
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("chain.json must exist at {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("chain.json must be valid json")
}

fn verdict_of(chain: &serde_json::Value) -> String {
    chain["verdict"]
        .as_str()
        .map_or_else(|| chain["verdict"].to_string(), str::to_owned)
}

fn pass_nodes(chain: &serde_json::Value) -> Vec<String> {
    chain["nodes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|n: &serde_json::Value| n["pass"].as_str().map(str::to_owned))
        .collect()
}

fn extracted_files(out: &Path) -> Vec<PathBuf> {
    let root: PathBuf = out.join("extracted");
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|e: std::fs::DirEntry| e.path())
        .filter(|p: &PathBuf| p.is_file())
        .collect();
    files.sort();
    files
}

fn winning_pick(bytes: &[u8], path_hint: &str) -> Option<DetectorPick> {
    let registry: PassRegistry = disrobe_passes::build_registry();
    let ctx: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: Some(path_hint),
        parent_hint: None,
        depth: 1,
    };
    let candidates: Vec<DetectVerdict> = registry.run_all(&ctx);
    registry.pick(candidates)
}

fn winner_id(rel: &str) -> String {
    let path: PathBuf = corpus_path(rel);
    let bytes: Vec<u8> = std::fs::read(&path).expect("corpus fixture must be readable");
    winning_pick(&bytes, rel).map_or_else(
        || "<none>".to_owned(),
        |p: DetectorPick| p.verdict.pass_id.to_owned(),
    )
}

#[test]
fn d_pe_report_is_terminal_and_never_re_detected_as_javascript() {
    let input: PathBuf = corpus_path("native/d/hello.d.exe");
    if !input.exists() {
        eprintln!("SKIP: d corpus fixture missing");
        return;
    }
    let out: disrobe_core::scratch::ScratchDir = tmp_out("d-report");
    let _: Output = run_auto(&input, out.path());
    let chain: serde_json::Value = chain_of(out.path());

    let passes: Vec<String> = pass_nodes(&chain);
    assert!(
        !passes.iter().any(|p: &String| p == "js.deob"),
        "a nativelang report must never be re-detected as javascript; nodes={passes:?}"
    );
    assert_eq!(
        verdict_of(&chain),
        "ok",
        "a chain that recovered a d image must not report an error; nodes={passes:?}"
    );

    let files: Vec<PathBuf> = extracted_files(out.path());
    let carries_rtti: bool = files.iter().any(|p: &PathBuf| {
        std::fs::read(p).is_ok_and(|b: Vec<u8>| b.windows(13).any(|w: &[u8]| w == b"hello.Greeter"))
    });
    assert!(
        carries_rtti,
        "the recovered d rtti dotted names must reach the user through auto output; files={files:?}"
    );
}

#[test]
fn prometheus_lua_receives_the_original_bytes_and_recovers_the_program() {
    let input: PathBuf = corpus_path("lua/prometheus/weak/obfuscated.lua");
    if !input.exists() {
        eprintln!("SKIP: lua corpus fixture missing");
        return;
    }
    let out: disrobe_core::scratch::ScratchDir = tmp_out("lua-prometheus");
    let _: Output = run_auto(&input, out.path());
    let chain: serde_json::Value = chain_of(out.path());

    let nodes: &[serde_json::Value] = chain["nodes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let lua_node: &serde_json::Value = nodes
        .iter()
        .find(|n: &&serde_json::Value| n["pass"].as_str() == Some("lua.deob"))
        .expect("lua.deob must run on a prometheus-obfuscated lua file");
    assert_eq!(
        lua_node["input_blake3"].as_str(),
        chain["input"]["blake3"].as_str(),
        "lua.deob must receive the original input bytes, not a previous pass report"
    );

    let recovered: PathBuf = out.path().join("extracted").join("lua-recovered.lua");
    let text: String = std::fs::read_to_string(&recovered)
        .unwrap_or_else(|e| panic!("recovered lua must exist at {}: {e}", recovered.display()));
    assert!(
        !text.contains("recovered windows script"),
        "the recovered lua must be the program, not a passed-through scriptlang report: {text}"
    );
    for token in ["print", "\"A\"", "\"B\"", "\"F\""] {
        assert!(
            text.contains(token),
            "recovered lua must carry the deobfuscated program token {token}: {text}"
        );
    }

    let manifest: PathBuf = out.path().join("extracted").join("lua.manifest.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).expect("manifest must exist"))
            .expect("manifest must be valid json");
    assert_eq!(
        doc["fully_recovered"],
        serde_json::Value::Bool(true),
        "auto must reach the same full recovery the pass reaches on the same bytes: {doc}"
    );
}

#[test]
fn a_report_is_not_re_fed_until_the_depth_cap() {
    let input: PathBuf = corpus_path("scriptlang/perl/hello.pl");
    if !input.exists() {
        eprintln!("SKIP: perl corpus fixture missing");
        return;
    }
    let out: disrobe_core::scratch::ScratchDir = tmp_out("perl-report-loop");
    let _: Output = run_auto(&input, out.path());
    let chain: serde_json::Value = chain_of(out.path());

    let passes: Vec<String> = pass_nodes(&chain);
    let scriptlang_nodes: usize = passes
        .iter()
        .filter(|p: &&String| p.as_str() == "scriptlang.classify")
        .count();
    assert_eq!(
        scriptlang_nodes, 1,
        "a pass report must not be re-fed to its own producer; nodes={passes:?}"
    );
    assert_ne!(
        verdict_of(&chain),
        "cap-reached",
        "report re-feeding must not burn the depth cap; nodes={passes:?}"
    );
}

#[test]
fn a_downstream_failure_does_not_discard_the_recovered_ancestor_output() {
    let input: PathBuf = corpus_path("shell/powershell/invoke-obfuscation/launcher/hello.ps1");
    if !input.exists() {
        eprintln!("SKIP: powershell corpus fixture missing");
        return;
    }
    let out: disrobe_core::scratch::ScratchDir = tmp_out("ps1-speculative");
    let _: Output = run_auto(&input, out.path());
    let chain: serde_json::Value = chain_of(out.path());

    let passes: Vec<String> = pass_nodes(&chain);
    assert_ne!(
        verdict_of(&chain),
        "error",
        "a speculative continuation failure must not erase a successful recovery; nodes={passes:?}"
    );
    assert!(
        !extracted_files(out.path()).is_empty(),
        "the successful ancestor output must still reach the user; nodes={passes:?}"
    );
}

fn corpus_files_under(root: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![corpus_path(root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(std::result::Result::ok) {
            let p: PathBuf = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn no_windows_or_unix_script_in_the_corpus_is_routed_to_a_foreign_language_pass() {
    const FOREIGN: [&str; 2] = ["lua.deob", "js.deob"];
    let mut checked: usize = 0;
    let mut misrouted: Vec<String> = Vec::new();
    for root in ["shell", "scriptlang"] {
        for file in corpus_files_under(root) {
            let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&file) else {
                continue;
            };
            if bytes.len() < 8 {
                continue;
            }
            let hint: String = file.display().to_string();
            let Some(pick): Option<DetectorPick> = winning_pick(&bytes, &hint) else {
                continue;
            };
            checked += 1;
            let id: &str = pick.verdict.pass_id;
            if FOREIGN.contains(&id) {
                misrouted.push(format!("{hint} -> {id}"));
            }
        }
    }
    assert!(
        checked > 20,
        "the script corpus sweep must actually exercise files; only {checked} were claimed"
    );
    assert!(
        misrouted.is_empty(),
        "a shell or scriptlang corpus file must never be claimed by a foreign-language pass: {misrouted:?}"
    );
}

#[test]
fn selection_prefers_a_named_obfuscator_over_the_broad_windows_script_family() {
    assert_eq!(
        winner_id("lua/prometheus/weak/obfuscated.lua"),
        "lua.deob",
        "a named lua obfuscator must outrank the broad windows-script heuristic"
    );
}

#[test]
fn selection_still_claims_a_genuine_windows_script_for_scriptlang() {
    assert_eq!(
        winner_id("shell/batch/seta/hello.bat"),
        "scriptlang.classify",
        "a genuine obfuscated batch script must still be claimed by scriptlang.classify"
    );
    assert_eq!(
        winner_id("shell/powershell/invoke-obfuscation/token/hello.ps1"),
        "scriptlang.classify",
        "a genuine obfuscated powershell script must still be claimed by scriptlang.classify"
    );
    for rel in [
        "shell/powershell/megafile/edge_cases.ps1",
        "shell/bash/megafile/edge_cases.sh",
        "shell/invoke-obfuscation/gauntlet/token_obfuscated.ps1",
        "shell/powershell/invoke-stealth/hello.ps1",
        "shell/batch/forsubstr/hello.bat",
    ] {
        assert_eq!(
            winner_id(rel),
            "scriptlang.classify",
            "the win-script recalibration must not hand {rel} to another pass"
        );
    }
}
