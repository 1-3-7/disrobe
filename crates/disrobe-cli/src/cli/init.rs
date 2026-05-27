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

const AGENTS_MD: &str = r"# AGENTS.md

This project is being analyzed with `disrobe` — a multi-language decompilation and deobfuscation suite.

## Hard rules

- Files under `out/01-*/` and `out/02-*/` are GROUND TRUTH artifacts. Do not edit; regenerate via `disrobe auto <input>`.
- All other files (analyst notes, hypotheses, renames) live under `.disrobe/notes/`.
- Use `disrobe explain <DR-CODE>` to look up any error code.
- Use `disrobe status` to inspect the current run's artifacts.

## Recommended workflow

1. `disrobe auto <input>` — sniffer-chain to produce baseline artifacts under `out/`.
2. `disrobe status` — see what was produced.
3. Read `out/chain.json` to understand the pass topology.
4. Iterate per-pass (`disrobe pyarmor unpack ...`, etc.) when you need finer control.
";

const MANIFEST_JSON: &str = r#"{
  "schema": "disrobe.project.manifest/v0",
  "version": "0.1.0",
  "notes_dir": ".disrobe/notes",
  "renames": {}
}
"#;

const CLAUDE_SETTINGS_JSON: &str = r#"{
  "permissions": {
    "deny": [
      "Edit(out/01-**)",
      "Edit(out/02-**)",
      "Write(out/01-**)",
      "Write(out/02-**)"
    ]
  }
}
"#;

const SLASH_VERIFY: &str = r"---
name: disrobe-verify
description: Verify the disrobe envelope at the given path.
---

Use `disrobe envelope verify $1` and report the result. Surface DR-CODES verbatim.
";

const SLASH_STATUS: &str = r"---
name: disrobe-status
description: Show the current disrobe run status.
---

Run `disrobe status` and summarize stages, artifacts, bytes, terminal reason.
";

const SLASH_RENAME: &str = r"---
name: disrobe-rename
description: Propose a rename for a symbol/file under out/.
---

Capture the proposed rename in `.disrobe/notes/renames.json`. Never edit ground-truth artifacts.
";

const SLASH_DIFF: &str = r"---
name: disrobe-diff
description: Diff the current out/ tree against a baseline directory.
---

Use git or `diff -ru` to compare. Highlight new / removed artifacts and bytes-changed.
";

const AIDER_CONF: &str = r"read:
  - AGENTS.md
  - .disrobe/manifest.json
auto-lint: false
";

pub(crate) fn run(ide: Option<IdeFlavor>, force: bool, fmt: OutputFormat) -> miette::Result<()> {
    let root: PathBuf = std::env::current_dir()
        .map_err(|e| miette::miette!("DR-CLI-0111: cannot read cwd: {e}"))?;
    let disrobe_dir: PathBuf = root.join(".disrobe");
    if disrobe_dir.exists() && !force {
        return Err(miette::miette!(
            "DR-CLI-0110: `.disrobe/` already exists at {} — pass `--force` to overwrite",
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
    created.push(agents_path);

    let manifest_path: PathBuf = disrobe_dir.join("manifest.json");
    write_file(&manifest_path, MANIFEST_JSON)?;
    created.push(manifest_path);

    let ide_label: Option<&'static str> = match ide {
        Some(IdeFlavor::Claude) => {
            let claude_dir: PathBuf = root.join(".claude");
            std::fs::create_dir_all(claude_dir.join("commands"))
                .map_err(|e| miette::miette!("DR-CLI-0111: cannot create .claude/commands: {e}"))?;
            let settings: PathBuf = claude_dir.join("settings.json");
            write_file(&settings, CLAUDE_SETTINGS_JSON)?;
            created.push(settings);
            for (name, body) in [
                ("disrobe-verify.md", SLASH_VERIFY),
                ("disrobe-status.md", SLASH_STATUS),
                ("disrobe-rename.md", SLASH_RENAME),
                ("disrobe-diff.md", SLASH_DIFF),
            ] {
                let p: PathBuf = claude_dir.join("commands").join(name);
                write_file(&p, body)?;
                created.push(p);
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
