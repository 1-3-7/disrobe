#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::cli_binary;

#[test]
fn agents_md_forensic_and_cross_ide_aliases() {
    let work: PathBuf = common::temp_dir("llm-agents");
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

    let canon: String = std::fs::read_to_string(work.join(".disrobe/AGENTS.md"))
        .expect(".disrobe/AGENTS.md must be written");

    let lc: String = canon.to_lowercase();
    for needle in [
        "ground truth",
        "chain of custody",
        "evidence",
        "out/01-",
        "out/02-",
    ] {
        assert!(
            lc.contains(needle),
            "AGENTS.md missing forensic marker: {needle}"
        );
    }
    assert!(
        lc.contains("immutable") || lc.contains("never edit"),
        "AGENTS.md must state the out/0x immutability rule"
    );

    for alias in [".cursorrules", ".windsurfrules", "CLAUDE.md"] {
        let p: PathBuf = work.join(alias);
        assert!(p.is_file(), "alias {alias} must exist");
        let got: String =
            std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {alias}: {e}"));
        assert_eq!(
            got, canon,
            "alias {alias} content must equal canonical AGENTS.md"
        );
    }
}
