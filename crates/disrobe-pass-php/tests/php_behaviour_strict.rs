#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::redundant_pub_crate,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use disrobe_pass_php::{Decompilation, RecoveryReport, RecoveryStage, recover_php};
use php_toolchain::{
    PHP_OPCACHE, PhpRun, PhpRuntime, compile_opcache_image, opcache_extension, require_php,
    unmeasured,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const PROGRAMS: [&str; 21] = [
    "anonymous",
    "arrays",
    "branches",
    "calls",
    "classes",
    "closures",
    "coalesce",
    "destructuring",
    "enums",
    "exceptions",
    "foreach_forms",
    "generators",
    "juggling",
    "loops",
    "operators",
    "references",
    "scopes",
    "statics",
    "strings",
    "switch_match",
    "switch_try",
];

const REFUSED: [(&str, &[&str]); 0] = [];

const MUTATION_PROGRAM: &str = "branches";

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn behaviour_dir() -> PathBuf {
    repository().join("corpus").join("php").join("behaviour")
}

fn program_source(program: &str) -> Vec<u8> {
    let path: PathBuf = behaviour_dir().join(format!("{program}.php"));
    std::fs::read(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "corpus/php/behaviour/{program}.php is tracked and graded here, so a run that cannot \
             read it must fail rather than grade less: {err} at {}",
            path.display()
        )
    })
}

struct Toolchain {
    php: PhpRuntime,
    opcache: PathBuf,
}

fn toolchain(graded: &str) -> Option<Toolchain> {
    let php: PhpRuntime = require_php(graded)?;
    let Some(opcache): Option<PathBuf> = opcache_extension(&php) else {
        unmeasured(
            &PHP_OPCACHE,
            graded,
            "the opcache extension was not found beside the php binary",
        );
        return None;
    };
    Some(Toolchain { php, opcache })
}

fn compile(toolchain: &Toolchain, program: &str, scratch: &Path) -> Result<Decompilation, String> {
    let image: Vec<u8> = compile_opcache_image(
        &toolchain.php,
        &toolchain.opcache,
        &program_source(program),
        scratch,
        program,
    )?;
    let report: RecoveryReport = recover_php(&image, None)
        .map_err(|err| format!("the file-cache image did not recover: {err}"))?;
    if report.stage != RecoveryStage::OpArrayDecompiled || report.php_kind != "OpcacheFileCache" {
        return Err(format!(
            "the file-cache image was routed to {:?} as {} instead of the op array decompiler",
            report.stage, report.php_kind
        ));
    }
    let decompiled: Decompilation = report
        .decompilation
        .ok_or_else(|| "the op array route returned no decompilation".to_owned())?;
    if decompiled.php_skeleton != report.output {
        return Err("the recovery output differs from the decompiled source it reports".to_owned());
    }
    Ok(decompiled)
}

fn original_stdout(php: &PhpRuntime, program: &str) -> Vec<u8> {
    let run: PhpRun =
        php.run_reporting_errors(&format!("{program} original"), &program_source(program));
    assert!(
        run.exited_clean && run.stderr.is_empty() && !run.stdout.is_empty(),
        "corpus/php/behaviour/{program}.php must run cleanly, print output and report nothing on \
         stderr, or the comparison grades nothing; exit clean {}, stderr `{}`",
        run.exited_clean,
        run.stderr
    );
    run.stdout
}

enum Outcome {
    Identical,
    Refused {
        containers: BTreeSet<String>,
        detail: String,
    },
    Diverged(String),
}

fn grade(toolchain: &Toolchain, program: &str, scratch: &Path) -> Outcome {
    let expected: Vec<u8> = original_stdout(&toolchain.php, program);
    let decompiled: Decompilation = match compile(toolchain, program, scratch) {
        Ok(decompiled) => decompiled,
        Err(defect) => return Outcome::Diverged(format!("no op array: {defect}")),
    };
    if !decompiled.unrecovered.is_empty() {
        let records: Vec<String> = decompiled
            .unrecovered
            .iter()
            .map(|refusal| {
                format!(
                    "{} op {} {}: {}",
                    refusal.container, refusal.index, refusal.mnemonic, refusal.reason
                )
            })
            .collect();
        return Outcome::Refused {
            containers: decompiled
                .unrecovered
                .iter()
                .map(|refusal| refusal.container.clone())
                .collect(),
            detail: format!(
                "{}\n--- recovered source ---\n{}",
                records.join("\n"),
                decompiled.php_skeleton
            ),
        };
    }
    let recovered: &str = &decompiled.php_skeleton;
    let run: PhpRun = toolchain
        .php
        .run_reporting_errors(&format!("{program} recovered"), recovered.as_bytes());
    if run.exited_clean && run.stderr.is_empty() && run.stdout == expected {
        return Outcome::Identical;
    }
    Outcome::Diverged(format!(
        "exit clean {}, stderr `{}`\n--- recovered source ---\n{recovered}\n--- original stdout \
         ---\n{}\n--- recovered stdout ---\n{}",
        run.exited_clean,
        run.stderr,
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(&run.stdout)
    ))
}

#[test]
fn every_behaviour_program_is_pinned_and_registered() {
    let dir: PathBuf = behaviour_dir();
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|err: std::io::Error| {
            panic!(
                "corpus/php/behaviour is tracked and graded, so a run that cannot list it must \
                 fail: {err} at {}",
                dir.display()
            )
        })
        .map(|entry| {
            entry
                .unwrap_or_else(|err: std::io::Error| panic!("list {}: {err}", dir.display()))
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter_map(|name: String| name.strip_suffix(".php").map(str::to_owned))
        .collect();
    let pinned: BTreeSet<String> = PROGRAMS
        .iter()
        .map(|name: &&str| (*name).to_owned())
        .collect();
    assert_eq!(pinned.len(), PROGRAMS.len(), "a program is pinned twice");
    assert_eq!(
        on_disk, pinned,
        "every behaviour program on disk must be pinned here and every pinned program must exist, \
         so adding or deleting one cannot change what is graded silently"
    );
    let manifest: String = std::fs::read_to_string(
        repository()
            .join("corpus")
            .join("php")
            .join("MANIFEST.toml"),
    )
    .expect("read corpus/php/MANIFEST.toml");
    for program in PROGRAMS {
        let entry: String = format!("name = \"behaviour/{program}.php\"");
        assert!(
            manifest.contains(&entry),
            "corpus/php/behaviour/{program}.php is not registered in corpus/php/MANIFEST.toml"
        );
    }
    let refused: BTreeSet<&str> = REFUSED.iter().map(|(name, _)| *name).collect();
    assert!(
        refused.iter().all(|name: &&str| PROGRAMS.contains(name)),
        "a refusal names a program that is not pinned: {refused:?}"
    );
}

#[test]
fn every_behaviour_program_recovers_to_identical_stdout_or_is_refused_by_name() {
    let graded: &str = "the strict php opcache behaviour set";
    let Some(toolchain): Option<Toolchain> = toolchain(graded) else {
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_php_behaviour")
            .expect("create the behaviour scratch directory");
    let expected_refusals: BTreeMap<&str, BTreeSet<String>> = REFUSED
        .iter()
        .map(|(program, containers)| {
            (
                *program,
                containers
                    .iter()
                    .map(|name: &&str| (*name).to_owned())
                    .collect(),
            )
        })
        .collect();
    let mut failures: Vec<String> = Vec::new();
    for program in PROGRAMS {
        let expected: Option<&BTreeSet<String>> = expected_refusals.get(program);
        match (grade(&toolchain, program, scratch.path()), expected) {
            (Outcome::Identical, None) => {}
            (Outcome::Identical, Some(containers)) => failures.push(format!(
                "{program} now recovers to identical output, so its refusal of {containers:?} is \
                 stale and must be removed"
            )),
            (
                Outcome::Refused {
                    containers: found, ..
                },
                Some(containers),
            ) if &found == containers => {}
            (
                Outcome::Refused {
                    containers: found,
                    detail,
                },
                _,
            ) => failures.push(format!(
                "{program} refused {found:?}, expected {expected:?}:\n{detail}"
            )),
            (Outcome::Diverged(detail), _) => {
                failures.push(format!("{program} diverged from the original: {detail}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} behaviour programs failed:\n\n{}",
        failures.len(),
        PROGRAMS.len(),
        failures.join("\n\n")
    );
}

#[test]
fn a_recovered_program_with_one_flipped_token_is_caught() {
    let graded: &str = "the strict php opcache behaviour set mutation control";
    let Some(toolchain): Option<Toolchain> = toolchain(graded) else {
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_php_behaviour_mutation")
            .expect("create the mutation scratch directory");
    let expected: Vec<u8> = original_stdout(&toolchain.php, MUTATION_PROGRAM);
    let recovered: String = compile(&toolchain, MUTATION_PROGRAM, scratch.path())
        .unwrap_or_else(|defect: String| panic!("{MUTATION_PROGRAM}: {defect}"))
        .php_skeleton;
    let flipped: String = recovered.replacen(" < ", " >= ", 1);
    assert_ne!(
        flipped, recovered,
        "the mutation control found no `<` comparison to flip in the recovered \
         {MUTATION_PROGRAM}, so it would grade nothing\n{recovered}"
    );
    let run: PhpRun = toolchain
        .php
        .run_reporting_errors("mutated recovery", flipped.as_bytes());
    assert_ne!(
        run.stdout, expected,
        "flipping the first `<` in the recovered {MUTATION_PROGRAM} left its output unchanged, so \
         the byte comparison cannot tell a wrong recovery from a right one"
    );
}
