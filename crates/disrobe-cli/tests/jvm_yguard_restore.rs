#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{cli_binary, run_disrobe, temp_dir};

fn corpus(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push(rel);
    p
}

#[test]
fn a_yguard_rename_log_restores_the_field_names_in_the_recovered_source_set() {
    let jar: PathBuf = corpus("corpus/jvm/obfuscators/yguard/real/Sample.rename.jar");
    let log: PathBuf = corpus("corpus/jvm/obfuscators/yguard/real/Sample.rename.renamelog.xml");
    for path in [&jar, &log] {
        assert!(
            path.exists(),
            "{} is tracked in git and this case grades nothing without it",
            path.display()
        );
    }
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing {} would leave this case driving nothing",
        cli_binary().display()
    );
    let log_text: String = std::fs::read_to_string(&log).expect("read rename log");
    for (original, obfuscated) in [("counter", "o00000"), ("checksum", "&#x00d2;00000")] {
        assert!(
            log_text.contains(&format!("name=\"{original}\" map=\"{obfuscated}\"")),
            "the yGuard log is the reference for {original}"
        );
    }

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-yguard-log");
    let out: PathBuf = scratch.path().to_path_buf();
    let run: common::Run = run_disrobe(&[
        "jvm",
        "decompile",
        jar.to_str().expect("utf8 jar"),
        "--out",
        out.to_str().expect("utf8 out"),
        "--yguard-log",
        log.to_str().expect("utf8 log"),
    ]);
    assert_eq!(
        run.code, 0,
        "jvm decompile --yguard-log failed: {}",
        run.stderr
    );

    let per_class: String = std::fs::read_to_string(out.join("com/example/app/Sample.java"))
        .expect("per-class source keeps the obfuscated names");
    assert!(per_class.contains("o00000"), "{per_class}");

    let recovered: String =
        std::fs::read_to_string(out.join("recovered/com/example/app/Sample.java"))
            .expect("recovered source set");
    for original in ["counter", "checksum"] {
        assert!(
            recovered.contains(original),
            "{original} missing from {recovered}"
        );
    }
    assert!(!recovered.contains("o00000"), "{recovered}");

    let summary: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.join("source-recovery.json")).expect("source-recovery.json"),
    )
    .expect("summary JSON");
    assert_eq!(summary["schema"], "disrobe.jvm.source-recovery/v1");
    assert!(
        summary["members_renamed"]
            .as_u64()
            .expect("members_renamed")
            >= 2
    );
    assert_eq!(summary["units"], 1);
}

#[test]
fn a_mapping_and_a_rename_log_together_are_refused() {
    let jar: PathBuf = corpus("corpus/jvm/obfuscators/yguard/real/Sample.rename.jar");
    let log: PathBuf = corpus("corpus/jvm/obfuscators/yguard/real/Sample.rename.renamelog.xml");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-yguard-conflict");
    let run: common::Run = run_disrobe(&[
        "jvm",
        "decompile",
        jar.to_str().expect("utf8 jar"),
        "--out",
        scratch.path().to_str().expect("utf8 out"),
        "--yguard-log",
        log.to_str().expect("utf8 log"),
        "--mapping",
        log.to_str().expect("utf8 log"),
    ]);
    assert_ne!(run.code, 0, "conflicting rename sources must be refused");
    assert!(run.stderr.contains("--mapping"), "{}", run.stderr);
}
