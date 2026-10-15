#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_core::scratch::ScratchDir;
use serde_json::Value;

const CLIENT_ENV: &[&str] = &[
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "GEMINI_CLI_HOME",
    "COPILOT_HOME",
    "QWEN_HOME",
    "KIMI_CODE_HOME",
    "XDG_CONFIG_HOME",
    "APPDATA",
    "LOCALAPPDATA",
];

struct Expect {
    agent: &'static str,
    config: PathBuf,
    container: &'static str,
    toml: bool,
    kind: Option<&'static str>,
    skill: Option<PathBuf>,
}

fn disrobe_bin() -> PathBuf {
    let bin: PathBuf = PathBuf::from(
        std::env::var_os("DISROBE_BIN")
            .expect("DISROBE_BIN must name the current disrobe binary built for this caller test"),
    );
    assert!(
        bin.is_file(),
        "DISROBE_BIN does not name a file: {}",
        bin.display()
    );
    bin
}

fn plain(path: &Path) -> String {
    let text: String = path.display().to_string();
    text.strip_prefix(r"\\?\")
        .filter(|rest: &&str| rest.as_bytes().get(1) == Some(&b':'))
        .map_or_else(|| text.clone(), str::to_owned)
}

fn expected_command() -> String {
    plain(&disrobe_bin().canonicalize().expect("canonical DISROBE_BIN"))
}

fn user_config(home: &Path, app: &str) -> PathBuf {
    if cfg!(windows) {
        home.join("AppData").join("Roaming").join(app)
    } else if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support").join(app)
    } else {
        home.join(".config").join(app)
    }
}

fn expectations(home: &Path) -> Vec<Expect> {
    let shared: PathBuf = home.join(".agents").join("skills");
    let skill = |dir: PathBuf| Some(dir.join("disrobe").join("SKILL.md"));
    let devin: PathBuf = if cfg!(windows) {
        home.join("AppData").join("Roaming").join("devin")
    } else {
        home.join(".config").join("devin")
    };
    vec![
        Expect {
            agent: "claude-code",
            config: home.join(".claude.json"),
            container: "mcpServers",
            toml: false,
            kind: Some("stdio"),
            skill: skill(home.join(".claude").join("skills")),
        },
        Expect {
            agent: "claude-desktop",
            config: user_config(home, "Claude").join("claude_desktop_config.json"),
            container: "mcpServers",
            toml: false,
            kind: None,
            skill: None,
        },
        Expect {
            agent: "codex",
            config: home.join(".codex").join("config.toml"),
            container: "mcp_servers",
            toml: true,
            kind: None,
            skill: skill(shared.clone()),
        },
        Expect {
            agent: "cursor",
            config: home.join(".cursor").join("mcp.json"),
            container: "mcpServers",
            toml: false,
            kind: Some("stdio"),
            skill: None,
        },
        Expect {
            agent: "gemini",
            config: home.join(".gemini").join("settings.json"),
            container: "mcpServers",
            toml: false,
            kind: None,
            skill: skill(shared.clone()),
        },
        Expect {
            agent: "vscode",
            config: user_config(home, "Code").join("User").join("mcp.json"),
            container: "servers",
            toml: false,
            kind: Some("stdio"),
            skill: None,
        },
        Expect {
            agent: "windsurf",
            config: home
                .join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            container: "mcpServers",
            toml: false,
            kind: None,
            skill: skill(home.join(".codeium").join("windsurf").join("skills")),
        },
        Expect {
            agent: "devin",
            config: devin.join("mcp_config.json"),
            container: "mcpServers",
            toml: false,
            kind: None,
            skill: skill(home.join(".codeium").join("windsurf").join("skills")),
        },
        Expect {
            agent: "copilot",
            config: home.join(".copilot").join("mcp-config.json"),
            container: "mcpServers",
            toml: false,
            kind: Some("local"),
            skill: skill(home.join(".copilot").join("skills")),
        },
        Expect {
            agent: "qwen",
            config: home.join(".qwen").join("settings.json"),
            container: "mcpServers",
            toml: false,
            kind: None,
            skill: skill(home.join(".qwen").join("skills")),
        },
        Expect {
            agent: "opencode",
            config: home.join(".config").join("opencode").join("opencode.json"),
            container: "mcp",
            toml: false,
            kind: Some("local"),
            skill: skill(home.join(".config").join("opencode").join("skills")),
        },
        Expect {
            agent: "kimi",
            config: home.join(".kimi-code").join("mcp.json"),
            container: "mcpServers",
            toml: false,
            kind: None,
            skill: skill(shared),
        },
    ]
}

fn agent(home: &Path, args: &[&str]) -> Output {
    let mut command: Command = Command::new(disrobe_bin());
    command.arg("agent").args(args).arg("--home").arg(home);
    for name in CLIENT_ENV {
        command.env_remove(name);
    }
    command
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .stdin(Stdio::null())
        .output()
        .expect("spawn disrobe agent")
}

fn succeed(home: &Path, args: &[&str]) -> Value {
    let output: Output = agent(home, args);
    assert!(
        output.status.success(),
        "disrobe agent {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error: serde_json::Error| {
        panic!(
            "disrobe agent {args:?} printed no JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn launch_of(entry: &Value) -> (String, Vec<String>) {
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .expect("argument array")
            .iter()
            .map(|item: &Value| item.as_str().expect("string argument").to_owned())
            .collect()
    };
    match &entry["command"] {
        Value::String(command) => (command.clone(), strings(&entry["args"])),
        argv @ Value::Array(_) => {
            let mut argv: Vec<String> = strings(argv);
            let command: String = argv.remove(0);
            (command, argv)
        }
        other => panic!("entry command is neither a string nor an argv array: {other}"),
    }
}

fn read_entry(expect: &Expect) -> Value {
    let text: String = std::fs::read_to_string(&expect.config).expect("read written config");
    let root: Value = if expect.toml {
        let parsed: toml::Value = toml::from_str(&text).expect("written config is valid TOML");
        serde_json::to_value(parsed).expect("TOML as JSON")
    } else {
        serde_json::from_str(&text).expect("written config is strict JSON")
    };
    root[expect.container]["disrobe"].clone()
}

fn backups(config: &Path) -> Vec<PathBuf> {
    let name: String = config.file_name().unwrap().to_string_lossy().into_owned();
    let prefix: String = format!("{name}.disrobe-backup-");
    let mut found: Vec<PathBuf> = std::fs::read_dir(config.parent().unwrap())
        .map(|entries: std::fs::ReadDir| {
            entries
                .filter_map(Result::ok)
                .map(|entry: std::fs::DirEntry| entry.path())
                .filter(|path: &PathBuf| {
                    path.file_name()
                        .is_some_and(|n: &std::ffi::OsStr| n.to_string_lossy().starts_with(&prefix))
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

#[test]
fn setup_writes_a_fresh_registration_and_skill_for_every_agent() {
    let command: String = expected_command();
    for probe in expectations(Path::new("probe")) {
        let home: ScratchDir = ScratchDir::create("agent-setup-fresh").expect("scratch home");
        let expect: Expect = expectations(home.path())
            .into_iter()
            .find(|e: &Expect| e.agent == probe.agent)
            .unwrap();
        let report: Value = succeed(
            home.path(),
            &["setup", "--agent", expect.agent, "--yes", "--json"],
        );
        assert_eq!(
            report["applied"],
            Value::Bool(true),
            "{}: {report}",
            expect.agent
        );
        let entry: Value = read_entry(&expect);
        let (written, args): (String, Vec<String>) = launch_of(&entry);
        assert_eq!(written, command, "{} registers this binary", expect.agent);
        assert_eq!(
            args,
            vec!["mcp".to_owned()],
            "{} runs `disrobe mcp`",
            expect.agent
        );
        assert_eq!(
            entry.get("type").and_then(Value::as_str),
            expect.kind,
            "{} entry type",
            expect.agent
        );
        if expect.toml {
            assert_eq!(entry["tool_timeout_sec"], Value::from(1800));
        }
        if let Some(skill) = &expect.skill {
            let text: String = std::fs::read_to_string(skill)
                .unwrap_or_else(|_| panic!("{} skill at {}", expect.agent, skill.display()));
            assert!(
                text.starts_with("---\nname: disrobe\n"),
                "{}",
                skill.display()
            );
            assert!(text.contains("open_target") && text.contains("run_command"));
        }
        assert!(
            backups(&expect.config).is_empty(),
            "a fresh file needs no backup"
        );
        let status: Value = succeed(home.path(), &["status", "--agent", expect.agent, "--json"]);
        let row: &Value = &status["agents"][0];
        assert_eq!(row["entry_present"], Value::Bool(true), "{row}");
        assert_eq!(row["matches_this_binary"], Value::Bool(true), "{row}");
        assert_eq!(
            row["skill_installed"],
            Value::Bool(expect.skill.is_some()),
            "{row}"
        );
    }
}

fn json_fixture(container: &str) -> (String, usize) {
    let head: String = format!(
        "{{\n    \"theme\": \"dark\",\n    \"{container}\": {{\n        \"other\": {{\n            \"command\": \"other-server\",\n            \"args\": [\"--flag\", \"caf\\u00e9\"]\n        }}"
    );
    let tail: &str = "\n    },\n    \"zeta\": [1, 2.5e3, {\"nested\": null}]\n}\n";
    (format!("{head}{tail}"), head.len())
}

#[test]
fn setup_keeps_unrelated_bytes_is_idempotent_and_remove_restores_the_file() {
    let command: String = expected_command();
    for probe in expectations(Path::new("probe")) {
        let home: ScratchDir = ScratchDir::create("agent-setup-existing").expect("scratch home");
        let expect: Expect = expectations(home.path())
            .into_iter()
            .find(|e: &Expect| e.agent == probe.agent)
            .unwrap();
        let (original, split): (String, usize) = if expect.toml {
            let head: &str = "model = \"o3\"\n\n# keep this comment\n[mcp_servers.other]\ncommand = \"other-server\"\nargs = [\"--flag\"]\n";
            let tail: &str = "\n[profiles.fast]\nmodel = \"o4-mini\"\n";
            (format!("{head}{tail}"), head.len())
        } else {
            json_fixture(expect.container)
        };
        std::fs::create_dir_all(expect.config.parent().unwrap()).unwrap();
        std::fs::write(&expect.config, &original).unwrap();

        succeed(
            home.path(),
            &["setup", "--agent", expect.agent, "--yes", "--json"],
        );
        let written: String = std::fs::read_to_string(&expect.config).unwrap();
        let (registered, _): (String, Vec<String>) = launch_of(&read_entry(&expect));
        assert_eq!(registered, command, "{}", expect.agent);
        if expect.toml {
            let parsed: toml::Value = toml::from_str(&written).unwrap();
            assert_eq!(parsed["model"].as_str(), Some("o3"));
            assert_eq!(
                parsed["mcp_servers"]["other"]["command"].as_str(),
                Some("other-server")
            );
            assert_eq!(
                parsed["profiles"]["fast"]["model"].as_str(),
                Some("o4-mini")
            );
            assert!(written.contains("# keep this comment"));
        } else {
            assert!(
                written.starts_with(&original[..split]) && written.ends_with(&original[split..]),
                "{}: bytes outside the disrobe entry changed:\n{written}",
                expect.agent
            );
            let parsed: Value = serde_json::from_str(&written).unwrap();
            assert_eq!(parsed["theme"], Value::from("dark"));
            assert_eq!(
                parsed[expect.container]["other"]["args"][1],
                Value::from("caf\u{e9}")
            );
        }
        let first_backups: Vec<PathBuf> = backups(&expect.config);
        assert_eq!(
            first_backups.len(),
            1,
            "{}: one backup per write",
            expect.agent
        );
        assert_eq!(
            std::fs::read_to_string(&first_backups[0]).unwrap(),
            original
        );

        let again: Value = succeed(
            home.path(),
            &["setup", "--agent", expect.agent, "--yes", "--json"],
        );
        assert_eq!(
            again["applied"],
            Value::Bool(false),
            "{}: {again}",
            expect.agent
        );
        assert_eq!(again["reason"], Value::from("nothing to change"));
        assert_eq!(std::fs::read_to_string(&expect.config).unwrap(), written);
        assert_eq!(
            backups(&expect.config).len(),
            1,
            "an unchanged file is not backed up"
        );

        let removed: Value = succeed(
            home.path(),
            &["remove", "--agent", expect.agent, "--yes", "--json"],
        );
        assert_eq!(
            removed["applied"],
            Value::Bool(true),
            "{}: {removed}",
            expect.agent
        );
        assert_eq!(
            std::fs::read_to_string(&expect.config).unwrap(),
            original,
            "{}: remove restores the original bytes",
            expect.agent
        );
        if let Some(skill) = &expect.skill {
            assert!(
                !skill.exists(),
                "{}: the skill goes with the last registration",
                expect.agent
            );
            assert!(
                !skill.parent().unwrap().exists(),
                "{}: an unmodified skill leaves no directory or backup",
                expect.agent
            );
        }
    }
}

#[test]
fn setup_edits_jsonc_comments_and_trailing_commas_in_place() {
    let home: ScratchDir = ScratchDir::create("agent-setup-jsonc").expect("scratch home");
    let expect: Expect = expectations(home.path())
        .into_iter()
        .find(|e: &Expect| e.agent == "vscode")
        .unwrap();
    let original: &str = "{\n  // servers I run\n  \"servers\": {\n    \"other\": { \"command\": \"x\", /* inline */ },\n  },\n  \"inputs\": [],\n}\n";
    std::fs::create_dir_all(expect.config.parent().unwrap()).unwrap();
    std::fs::write(&expect.config, original).unwrap();
    succeed(
        home.path(),
        &["setup", "--agent", "vscode", "--yes", "--json"],
    );
    let written: String = std::fs::read_to_string(&expect.config).unwrap();
    assert!(written.contains("// servers I run") && written.contains("/* inline */"));
    assert!(written.contains("\"disrobe\": {"), "{written}");
    let status: Value = succeed(home.path(), &["status", "--agent", "vscode", "--json"]);
    assert_eq!(
        status["agents"][0]["matches_this_binary"],
        Value::Bool(true),
        "{status}"
    );
    succeed(
        home.path(),
        &["remove", "--agent", "vscode", "--yes", "--json"],
    );
    assert_eq!(std::fs::read_to_string(&expect.config).unwrap(), original);
}

#[test]
fn malformed_configs_are_refused_by_name_without_writing() {
    for (agent_name, text) in [
        (
            "cursor",
            "{\"mcpServers\": {\"other\": {\"command\": \"x\"}",
        ),
        ("gemini", "{\"mcpServers\": [1, 2]}"),
        ("codex", "[mcp_servers.other\ncommand = \"x\"\n"),
    ] {
        let home: ScratchDir = ScratchDir::create("agent-setup-malformed").expect("scratch home");
        let expect: Expect = expectations(home.path())
            .into_iter()
            .find(|e: &Expect| e.agent == agent_name)
            .unwrap();
        std::fs::create_dir_all(expect.config.parent().unwrap()).unwrap();
        std::fs::write(&expect.config, text).unwrap();
        let output: Output = agent(home.path(), &["setup", "--agent", agent_name, "--yes"]);
        let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            !output.status.success(),
            "{agent_name}: malformed config accepted"
        );
        assert!(stderr.contains("DR-CLI-0964"), "{agent_name}: {stderr}");
        let unwrapped: String = stderr
            .chars()
            .filter(|c: &char| !c.is_whitespace() && *c != '\u{2502}')
            .collect();
        assert!(
            unwrapped.contains(&plain(&expect.config)),
            "{agent_name}: refusal names the file: {stderr}"
        );
        assert_eq!(std::fs::read_to_string(&expect.config).unwrap(), text);
        assert!(backups(&expect.config).is_empty());
        if let Some(skill) = &expect.skill {
            assert!(!skill.exists(), "{agent_name}: nothing else was written");
        }
    }
}

#[test]
fn dry_runs_and_unconfirmed_runs_print_the_diff_and_write_nothing() {
    let home: ScratchDir = ScratchDir::create("agent-setup-dry").expect("scratch home");
    let expect: Expect = expectations(home.path())
        .into_iter()
        .find(|e: &Expect| e.agent == "claude-code")
        .unwrap();
    for args in [
        &["setup", "--agent", "claude-code", "--dry-run"][..],
        &["setup", "--agent", "claude-code"][..],
    ] {
        let output: Output = agent(home.path(), args);
        let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("--- /dev/null") && stdout.contains("+    \"disrobe\": {"),
            "{stdout}"
        );
        assert!(stdout.contains("nothing written"), "{stdout}");
        assert!(
            !expect.config.exists(),
            "{args:?} wrote {}",
            expect.config.display()
        );
        assert!(!expect.skill.as_ref().unwrap().exists());
    }
}

#[test]
fn setup_records_requested_roots_and_rejects_missing_ones() {
    let home: ScratchDir = ScratchDir::create("agent-setup-roots").expect("scratch home");
    let root: ScratchDir = ScratchDir::create("agent-setup-root").expect("scratch root");
    let expect: Expect = expectations(home.path())
        .into_iter()
        .find(|e: &Expect| e.agent == "cursor")
        .unwrap();
    let root_arg: String = root.path().display().to_string();
    succeed(
        home.path(),
        &[
            "setup", "--agent", "cursor", "--root", &root_arg, "--yes", "--json",
        ],
    );
    let (_, args): (String, Vec<String>) = launch_of(&read_entry(&expect));
    assert_eq!(
        args,
        vec![
            "mcp".to_owned(),
            "--root".to_owned(),
            plain(&root.path().canonicalize().unwrap())
        ]
    );
    let missing: String = root.path().join("absent").display().to_string();
    let output: Output = agent(
        home.path(),
        &["setup", "--agent", "cursor", "--root", &missing, "--yes"],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("DR-CLI-0962"));
}

#[test]
fn setup_follows_each_agent_home_override() {
    let home: ScratchDir = ScratchDir::create("agent-setup-env").expect("scratch home");
    let claude_dir: PathBuf = home.path().join("claude-alt");
    let mut command: Command = Command::new(disrobe_bin());
    command.args([
        "agent",
        "setup",
        "--agent",
        "codex",
        "--agent",
        "claude-code",
        "--yes",
        "--json",
    ]);
    for name in CLIENT_ENV {
        command.env_remove(name);
    }
    let output: Output = command
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .env("APPDATA", home.path().join("AppData").join("Roaming"))
        .env("LOCALAPPDATA", home.path().join("AppData").join("Local"))
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("CODEX_HOME", "~/codex-alt")
        .env("CLAUDE_CONFIG_DIR", &claude_dir)
        .stdin(Stdio::null())
        .output()
        .expect("spawn disrobe agent setup");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(home.path().join("codex-alt").join("config.toml").is_file());
    assert!(!home.path().join(".codex").exists());
    assert!(claude_dir.join(".claude.json").is_file());
    assert!(!home.path().join(".claude.json").exists());
    assert!(
        claude_dir
            .join("skills")
            .join("disrobe")
            .join("SKILL.md")
            .is_file()
    );
    assert!(
        home.path()
            .join(".agents")
            .join("skills")
            .join("disrobe")
            .join("SKILL.md")
            .is_file()
    );
}
