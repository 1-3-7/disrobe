#![allow(clippy::needless_pass_by_value)]

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::output::{OutputFormat, emit};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum IdeFlavor {
    Claude,
    Cursor,
    Windsurf,
    Aider,
}

#[derive(Debug, Serialize)]
pub(crate) struct InitReport {
    pub root: String,
    pub created: Vec<String>,
    pub ide: Option<&'static str>,
}

const AGENTS_MD: &str = r"# AGENTS.md - forensic analysis protocol

You are operating inside a `disrobe` workspace. Treat every artifact under `out/`
as forensic evidence subject to chain of custody. Do not tamper with it.

## Chain of custody (hard rules)

- `out/01-*/` and `out/02-*/` are GROUND TRUTH evidence stages. They are immutable.
  Never edit them. Regenerate only via `disrobe auto <input>`.
- Analyst notes, hypotheses, and renames are derived work - they live ONLY under
  `.disrobe/notes/`. Keep evidence and analysis separated.
- Every claim about the target must trace back to a ground-truth artifact under `out/`.
- Use `disrobe explain <DR-CODE>` to resolve any error code verbatim.
- Use `disrobe status` to enumerate the current run's evidence and stages.

## Workflow

1. `disrobe auto <input>` - produce baseline evidence under `out/`.
2. `disrobe status` - inventory what was produced.
3. Read `out/chain.json` for the pass topology.
4. Iterate per-pass (`disrobe pyarmor unpack ...`) when finer control is needed;
   write only to `.disrobe/notes/`.
";

const MANIFEST_JSON: &str = r#"{
  "schema": "disrobe.project.manifest/v0",
  "version": "0.1.0",
  "notes_dir": ".disrobe/notes",
  "renames": {}
}
"#;

#[derive(Debug, Serialize)]
struct ClaudeSettings {
    permissions: ClaudePermissions,
    hooks: ClaudeHooks,
}

#[derive(Debug, Serialize)]
struct ClaudePermissions {
    deny: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct ClaudeHooks {
    #[serde(rename = "SessionStart")]
    session_start: Vec<HookMatcher>,
    #[serde(rename = "UserPromptSubmit")]
    user_prompt_submit: Vec<HookMatcher>,
    #[serde(rename = "PreToolUse")]
    pre_tool_use: Vec<HookMatcher>,
    #[serde(rename = "PostToolUse")]
    post_tool_use: Vec<HookMatcher>,
}

#[derive(Debug, Serialize)]
struct HookMatcher {
    #[serde(skip_serializing_if = "str::is_empty")]
    matcher: &'static str,
    hooks: Vec<HookCommand>,
}

#[derive(Debug, Serialize)]
struct HookCommand {
    #[serde(rename = "type")]
    kind: &'static str,
    command: &'static str,
}

const CLAUDE_DENY_GLOBS: [&str; 4] = [
    "Edit(out/01-**)",
    "Edit(out/02-**)",
    "Write(out/01-**)",
    "Write(out/02-**)",
];

const PRETOOL_DENY_GUARD: &str = r#"f="$CLAUDE_TOOL_INPUT_FILE_PATH"; case "$f" in out/01-*|out/02-*) echo "DR-CLI-0113: out/01-* and out/02-* are ground-truth evidence stages; refusing write to $f" >&2; exit 2;; esac"#;

const SESSION_START_CMD: &str = r#"echo "disrobe workspace: out/01-* and out/02-* are immutable ground-truth evidence stages.""#;
const USER_PROMPT_CMD: &str = r#"echo "reminder: treat out/ artifacts as chain-of-custody evidence; analyst notes -> .disrobe/notes/.""#;
const POST_TOOL_CMD: &str = r"disrobe status >/dev/null 2>&1 || true";

fn claude_settings() -> ClaudeSettings {
    let pre: HookMatcher = HookMatcher {
        matcher: "Edit|Write",
        hooks: vec![HookCommand {
            kind: "command",
            command: PRETOOL_DENY_GUARD,
        }],
    };
    let post: HookMatcher = HookMatcher {
        matcher: "Edit|Write",
        hooks: vec![HookCommand {
            kind: "command",
            command: POST_TOOL_CMD,
        }],
    };
    let session: HookMatcher = HookMatcher {
        matcher: "",
        hooks: vec![HookCommand {
            kind: "command",
            command: SESSION_START_CMD,
        }],
    };
    let prompt: HookMatcher = HookMatcher {
        matcher: "",
        hooks: vec![HookCommand {
            kind: "command",
            command: USER_PROMPT_CMD,
        }],
    };
    ClaudeSettings {
        permissions: ClaudePermissions {
            deny: CLAUDE_DENY_GLOBS.to_vec(),
        },
        hooks: ClaudeHooks {
            session_start: vec![session],
            user_prompt_submit: vec![prompt],
            pre_tool_use: vec![pre],
            post_tool_use: vec![post],
        },
    }
}

struct SlashCommand {
    file_stem: &'static str,
    name: &'static str,
    description: &'static str,
    subcommand: &'static str,
    body: &'static str,
}

const SLASH_COMMANDS: &[SlashCommand] = &[
    SlashCommand {
        file_stem: "disrobe-verify",
        name: "disrobe-verify",
        description: "Verify the disrobe envelope at the given path.",
        subcommand: "disrobe envelope verify",
        body: "Run `disrobe envelope verify $1` & report the result. Surface DR-CODES (e.g. DR-CLI-0080, DR-CLI-0087) verbatim.",
    },
    SlashCommand {
        file_stem: "disrobe-status",
        name: "disrobe-status",
        description: "Show the current disrobe run status.",
        subcommand: "disrobe status",
        body: "Run `disrobe status` & summarize stages, artifacts, bytes, & terminal reason.",
    },
    SlashCommand {
        file_stem: "disrobe-rename",
        name: "disrobe-rename",
        description: "Propose a rename for a symbol/file under out/.",
        subcommand: "disrobe status",
        body: "Capture the proposed rename in `.disrobe/notes/renames.json` against the `disrobe.project.manifest/v0` manifest. Confirm context first with `disrobe status`. Never edit ground-truth artifacts under out/01-** or out/02-**.",
    },
    SlashCommand {
        file_stem: "disrobe-diff",
        name: "disrobe-diff",
        description: "Diff the current out/ tree against a baseline directory.",
        subcommand: "disrobe status",
        body: "Run `disrobe status` to enumerate the current out/ tree, then use git or `diff -ru` to compare against the baseline $1. Highlight new / removed artifacts & bytes-changed.",
    },
];

const fn body_references_subcommand(body: &str, subcommand: &str) -> bool {
    let (body_bytes, sub_bytes): (&[u8], &[u8]) = (body.as_bytes(), subcommand.as_bytes());
    if sub_bytes.is_empty() {
        return true;
    }
    if sub_bytes.len() > body_bytes.len() {
        return false;
    }
    let mut start: usize = 0;
    while start + sub_bytes.len() <= body_bytes.len() {
        let mut i: usize = 0;
        while i < sub_bytes.len() && body_bytes[start + i] == sub_bytes[i] {
            i += 1;
        }
        if i == sub_bytes.len() {
            return true;
        }
        start += 1;
    }
    false
}

const _: () = {
    let mut i: usize = 0;
    while i < SLASH_COMMANDS.len() {
        assert!(
            body_references_subcommand(SLASH_COMMANDS[i].body, SLASH_COMMANDS[i].subcommand),
            "slash command body must reference its real disrobe subcommand"
        );
        i += 1;
    }
};

fn render_slash_command(cmd: &SlashCommand) -> String {
    format!(
        "---\nname: {name}\ndescription: {description}\n---\n\n{body}\n",
        name = cmd.name,
        description = cmd.description,
        body = cmd.body,
    )
}

const AIDER_CONF: &str = r"read:
  - AGENTS.md
  - .disrobe/manifest.json
auto-lint: false
";

const CLAUDE_ALIASES: [&str; 3] = [".cursorrules", ".windsurfrules", "CLAUDE.md"];

#[cfg(unix)]
fn try_symlink(canonical: &Path, alias: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(canonical, alias)
}

#[cfg(windows)]
fn try_symlink(canonical: &Path, alias: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(canonical, alias)
}

#[cfg(not(any(unix, windows)))]
fn try_symlink(_canonical: &Path, _alias: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

fn link_or_copy(canonical: &Path, alias: &Path) -> miette::Result<()> {
    let _: std::io::Result<()> = std::fs::remove_file(alias);
    if try_symlink(canonical, alias).is_ok() {
        return Ok(());
    }
    std::fs::copy(canonical, alias)
        .map(|_n: u64| ())
        .map_err(|e| {
            miette::miette!(
                "DR-CLI-0115: cannot alias {} -> {}: {e}",
                alias.display(),
                canonical.display()
            )
        })
}

pub(crate) fn run(ide: Option<IdeFlavor>, force: bool, fmt: OutputFormat) -> miette::Result<()> {
    let root: PathBuf = std::env::current_dir()
        .map_err(|e| miette::miette!("DR-CLI-0111: cannot read cwd: {e}"))?;
    let disrobe_dir: PathBuf = root.join(".disrobe");
    if disrobe_dir.exists() && !force {
        return Err(miette::miette!(
            "DR-CLI-0110: `.disrobe/` already exists at {} - pass `--force` to overwrite",
            disrobe_dir.display()
        ));
    }
    std::fs::create_dir_all(&disrobe_dir)
        .map_err(|e| miette::miette!("DR-CLI-0111: cannot create .disrobe: {e}"))?;
    std::fs::create_dir_all(disrobe_dir.join("notes"))
        .map_err(|e| miette::miette!("DR-CLI-0111: cannot create .disrobe/notes: {e}"))?;

    let mut created: Vec<PathBuf> = Vec::new();

    let agents_path: PathBuf = disrobe_dir.join("AGENTS.md");
    write_file(&agents_path, AGENTS_MD)?;
    created.push(agents_path.clone());

    let manifest_path: PathBuf = disrobe_dir.join("manifest.json");
    write_file(&manifest_path, MANIFEST_JSON)?;
    created.push(manifest_path);

    let ide_label: Option<&'static str> = match ide {
        Some(IdeFlavor::Claude) => {
            let claude_dir: PathBuf = root.join(".claude");
            std::fs::create_dir_all(claude_dir.join("commands"))
                .map_err(|e| miette::miette!("DR-CLI-0111: cannot create .claude/commands: {e}"))?;
            let settings: PathBuf = claude_dir.join("settings.json");
            let settings_model: ClaudeSettings = claude_settings();
            let settings_json: String =
                serde_json::to_string_pretty(&settings_model).map_err(|e| {
                    miette::miette!("DR-CLI-0114: cannot serialize .claude/settings.json: {e}")
                })?;
            write_file(&settings, &settings_json)?;
            created.push(settings);
            for cmd in SLASH_COMMANDS {
                let rendered: String = render_slash_command(cmd);
                let p: PathBuf = claude_dir
                    .join("commands")
                    .join(format!("{}.md", cmd.file_stem));
                write_file(&p, &rendered)?;
                created.push(p);
            }
            for alias in CLAUDE_ALIASES {
                let alias_path: PathBuf = root.join(alias);
                link_or_copy(&agents_path, &alias_path)?;
                created.push(alias_path);
            }
            Some("claude")
        }
        Some(IdeFlavor::Cursor) => {
            let p: PathBuf = root.join(".cursorrules");
            write_file(&p, AGENTS_MD)?;
            created.push(p);
            Some("cursor")
        }
        Some(IdeFlavor::Windsurf) => {
            let p: PathBuf = root.join(".windsurfrules");
            write_file(&p, AGENTS_MD)?;
            created.push(p);
            Some("windsurf")
        }
        Some(IdeFlavor::Aider) => {
            let p: PathBuf = root.join(".aider.conf.yml");
            write_file(&p, AIDER_CONF)?;
            created.push(p);
            Some("aider")
        }
        None => None,
    };

    let report: InitReport = InitReport {
        root: root.display().to_string(),
        created: created.iter().map(|p| p.display().to_string()).collect(),
        ide: ide_label,
    };
    emit(fmt, &report, || {
        println!("disrobe init: OK");
        println!("  root:    {}", report.root);
        println!("  ide:     {}", report.ide.unwrap_or("(none)"));
        println!("  created:");
        for c in &report.created {
            println!("    - {c}");
        }
    })
}

fn write_file(path: &Path, contents: &str) -> miette::Result<()> {
    std::fs::write(path, contents.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0112: cannot write {}: {e}", path.display()))
}
