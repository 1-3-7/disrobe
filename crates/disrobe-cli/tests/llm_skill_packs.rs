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

fn temp_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-skills-{tag}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

struct ExpectedSkill {
    dir_name: &'static str,
    name: &'static str,
    subcommand: &'static str,
    keyword: &'static str,
}

const EXPECTED: &[ExpectedSkill; 7] = &[
    ExpectedSkill {
        dir_name: "verify-decompilation",
        name: "verify-decompilation",
        subcommand: "disrobe envelope verify",
        keyword: "roundtrip",
    },
    ExpectedSkill {
        dir_name: "recover-symbol-names",
        name: "recover-symbol-names",
        subcommand: "disrobe status",
        keyword: "renames.json",
    },
    ExpectedSkill {
        dir_name: "reconstruct-imports",
        name: "reconstruct-imports",
        subcommand: "disrobe status",
        keyword: "import graph",
    },
    ExpectedSkill {
        dir_name: "confidence-audit",
        name: "confidence-audit",
        subcommand: "disrobe status",
        keyword: "low-confidence",
    },
    ExpectedSkill {
        dir_name: "escalate-to-dynamic",
        name: "escalate-to-dynamic",
        subcommand: "disrobe status",
        keyword: "dynamic trace",
    },
    ExpectedSkill {
        dir_name: "diff-against-pypi",
        name: "diff-against-pypi",
        subcommand: "disrobe status",
        keyword: "PyPI",
    },
    ExpectedSkill {
        dir_name: "patch-and-roundtrip",
        name: "patch-and-roundtrip",
        subcommand: "disrobe envelope verify",
        keyword: "minimal patch",
    },
];

#[test]
fn init_claude_emits_seven_skill_packs_with_distinct_bodies() {
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

    let skills_dir: PathBuf = work.join(".disrobe").join("skills");
    let mut bodies: Vec<String> = Vec::with_capacity(EXPECTED.len());
    for es in EXPECTED {
        let path: PathBuf = skills_dir.join(es.dir_name).join("SKILL.md");
        let content: String = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        assert!(
            content.starts_with("---\n"),
            "{} missing front-matter open",
            es.dir_name
        );
        assert!(
            content.contains(&format!("name: {}\n", es.name)),
            "{} missing front-matter name `{}`",
            es.dir_name,
            es.name
        );
        let desc_marker: &str = "description: ";
        let desc_idx: usize = content
            .find(desc_marker)
            .unwrap_or_else(|| panic!("{} missing description", es.dir_name));
        let desc_rest: &str = &content[desc_idx + desc_marker.len()..];
        let desc_line: &str = desc_rest.lines().next().unwrap_or("");
        assert!(
            !desc_line.trim().is_empty(),
            "{} has empty description",
            es.dir_name
        );
        assert!(
            content.contains(es.subcommand),
            "{} body must reference real subcommand `{}`; got:\n{}",
            es.dir_name,
            es.subcommand,
            content
        );
        assert!(
            content.contains(es.keyword),
            "{} body must contain distinctive keyword `{}`; got:\n{}",
            es.dir_name,
            es.keyword,
            content
        );
        bodies.push(content);
    }

    let distinct: BTreeSet<&String> = bodies.iter().collect();
    assert_eq!(
        distinct.len(),
        EXPECTED.len(),
        "skill pack bodies must be pairwise-distinct (no stub duplication)"
    );
}

#[test]
fn skill_pack_count_is_exactly_seven() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("count");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let bin: PathBuf = cli_binary();
    let _: Output = Command::new(&bin)
        .args(["init", "--ide", "claude"])
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    let skills_dir: PathBuf = work.join(".disrobe").join("skills");
    let count: usize = std::fs::read_dir(&skills_dir)
        .expect("read skills dir")
        .filter_map(Result::ok)
        .filter(|e: &std::fs::DirEntry| e.path().is_dir())
        .count();
    assert_eq!(count, 7, "expected exactly seven skill packs");
}
