#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;
use std::process::Command;

use common::cli_binary;

#[test]
fn claude_settings_has_typed_hooks_and_pretool_deny() {
    let work_scratch: disrobe_core::scratch::ScratchDir = common::temp_dir("llm-settings");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} -- run `cargo build -p disrobe-cli` first",
        bin.display()
    );

    let output: std::process::Output = Command::new(&bin)
        .args(["init", "--ide", "claude"])
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe init");
    assert_eq!(
        output.status.code(),
        Some(0),
        "init must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let raw: String = std::fs::read_to_string(work.join(".claude/settings.json"))
        .expect(".claude/settings.json must be written");
    let v: serde_json::Value =
        serde_json::from_str(&raw).expect("settings.json must be valid json");

    let hooks: &serde_json::Value = v.get("hooks").expect("hooks");
    for key in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
    ] {
        assert!(
            hooks.get(key).and_then(|h| h.as_array()).is_some(),
            "missing hook event {key}"
        );
    }

    let pre: &serde_json::Value = &hooks["PreToolUse"][0]["hooks"][0]["command"];
    let cmd: &str = pre.as_str().expect("pretool command is string");
    assert!(
        cmd.contains("disrobe guard check") && cmd.contains("CLAUDE_TOOL_INPUT_FILE_PATH"),
        "PreToolUse must call disrobe guard check on Claude's input path; got: {cmd}"
    );
    assert_eq!(
        hooks["PreToolUse"][0]["matcher"].as_str(),
        Some("Edit|Write"),
        "PreToolUse matcher must be Edit|Write"
    );

    let deny: &Vec<serde_json::Value> = v["permissions"]["deny"]
        .as_array()
        .expect("permissions.deny must be an array");
    let deny_strs: Vec<&str> = deny.iter().filter_map(|d| d.as_str()).collect();
    assert!(
        deny_strs.contains(&"Edit(out/01-**)"),
        "permissions.deny must contain Edit(out/01-**)"
    );
    assert!(
        deny_strs.contains(&"Write(out/02-**)"),
        "permissions.deny must contain Write(out/02-**)"
    );
}
