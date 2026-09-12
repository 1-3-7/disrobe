#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

fn cli_binary() -> PathBuf {
    let mut p: PathBuf = std::env::current_exe().expect("test exe path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    assert!(p.is_file(), "disrobe binary missing at {}", p.display());
    p
}

fn live_subcommand_paths() -> BTreeSet<String> {
    let bin: PathBuf = cli_binary();
    let out: Output = Command::new(&bin)
        .arg("subcommand-tree")
        .output()
        .expect("spawn disrobe subcommand-tree");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "subcommand-tree stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

fn temp_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-slash-{tag}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

struct ExpectedCommand {
    file: &'static str,
    name: &'static str,
    subcommand: &'static str,
}

const EXPECTED: &[ExpectedCommand] = &[
    ExpectedCommand {
        file: "disrobe-verify.md",
        name: "disrobe-verify",
        subcommand: "disrobe envelope verify",
    },
    ExpectedCommand {
        file: "disrobe-status.md",
        name: "disrobe-status",
        subcommand: "disrobe status",
    },
    ExpectedCommand {
        file: "disrobe-rename.md",
        name: "disrobe-rename",
        subcommand: "disrobe status",
    },
    ExpectedCommand {
        file: "disrobe-diff.md",
        name: "disrobe-diff",
        subcommand: "disrobe status",
    },
];

#[test]
fn init_claude_emits_typed_slash_commands_with_real_subcommands() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("typed");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let bin: PathBuf = cli_binary();
    let out: Output = Command::new(&bin)
        .args(["init", "--ide", "claude"])
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let live_paths: BTreeSet<String> = live_subcommand_paths();
    let commands_dir: PathBuf = work.join(".claude").join("commands");
    for ec in EXPECTED {
        let path: PathBuf = commands_dir.join(ec.file);
        let content: String = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        assert!(
            content.starts_with("---\n"),
            "{} missing front-matter open",
            ec.file
        );
        assert!(
            content.contains(&format!("name: {}\n", ec.name)),
            "{} missing front-matter name `{}`",
            ec.file,
            ec.name
        );
        assert!(
            content.contains("description: "),
            "{} missing description",
            ec.file
        );
        assert!(
            content.contains(ec.subcommand),
            "{} body must reference real subcommand `{}`; got:\n{}",
            ec.file,
            ec.subcommand,
            content
        );
        let path_only: &str = ec
            .subcommand
            .strip_prefix("disrobe ")
            .unwrap_or(ec.subcommand);
        assert!(
            live_paths.contains(path_only),
            "{} names `{}`, which is not a subcommand path the live clap tree reports; \
             live paths: {live_paths:?}",
            ec.file,
            ec.subcommand
        );
    }
}

#[test]
fn slash_command_count_is_exactly_four() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("count");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let bin: PathBuf = cli_binary();
    let _: Output = Command::new(&bin)
        .args(["init", "--ide", "claude"])
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    let commands_dir: PathBuf = work.join(".claude").join("commands");
    let count: usize = std::fs::read_dir(&commands_dir)
        .expect("read commands dir")
        .filter_map(Result::ok)
        .filter(|e: &std::fs::DirEntry| e.path().extension().and_then(|x| x.to_str()) == Some("md"))
        .count();
    assert_eq!(count, 4, "expected exactly four slash commands");
}
