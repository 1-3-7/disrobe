#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::print_stdout,
    clippy::print_stderr,
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

use std::any::Any;
use std::collections::BTreeSet;
use std::panic::UnwindSafe;
use std::path::PathBuf;

use disrobe_pass_php::{RecoveryReport, RecoveryStage, recover_php};
use php_toolchain::{
    PhpRun, PhpRuntime, require_php, required_fixture, residual_decode_primitives, with_open_tag,
};

const GRADED: &str =
    "the php eval-chain corpus, each recovered file re-executed under the real php interpreter";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceMatch {
    Exact,
    ExactModuloTrailingNewline,
    Reformatted,
    PlainPassthrough,
    NoBodyRecovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Behavior {
    MatchesOriginal,
    WalledWithoutFabricating,
}

#[derive(Debug, Clone, Copy)]
struct Golden {
    fixture: &'static str,
    stage: RecoveryStage,
    source_match: SourceMatch,
    behavior: Behavior,
}

const GOLDEN: [Golden; 24] = [
    Golden {
        fixture: "c_octal_inline.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "c_octal_loader.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "clean_control.php",
        stage: RecoveryStage::PlainSource,
        source_match: SourceMatch::PlainPassthrough,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "h_hexname.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "h_htmlwrap.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "h_packhex.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "p_decoy.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "p_deep5.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "p_globals.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "p_preg.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "p_preg2.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "r_gotochain.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Reformatted,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "runtime_key.php",
        stage: RecoveryStage::PlainSource,
        source_match: SourceMatch::NoBodyRecovered,
        behavior: Behavior::WalledWithoutFabricating,
    },
    Golden {
        fixture: "s_doubleb64.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::Exact,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_arith_fname.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_concat_fname.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_createfunc.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_double_gz_b64.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_globals_chain.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_globals_curly.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_hex2bin.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_implode_array.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_strrev_rot13_gz.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
    Golden {
        fixture: "x_substr_fname.php",
        stage: RecoveryStage::EvalChainPeeled,
        source_match: SourceMatch::ExactModuloTrailingNewline,
        behavior: Behavior::MatchesOriginal,
    },
];

const EXPECTED_REL: &str = "php_real_chains/EXPECTED.txt";

fn fixtures_on_disk() -> BTreeSet<String> {
    let dir: PathBuf = php_toolchain::fixture_path("php_real_chains");
    let entries: std::fs::ReadDir = std::fs::read_dir(&dir).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "the eval-chain corpus at {} is tracked in this repository and every statement this \
             crate makes about chain recovery is graded over it, so a run that cannot enumerate it \
             must fail rather than grade an empty set: {err}",
            dir.display()
        )
    });
    let mut names: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let entry: std::fs::DirEntry =
            entry.unwrap_or_else(|err: std::io::Error| panic!("read {}: {err}", dir.display()));
        let name: String = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".php") {
            let inserted: bool = names.insert(name.clone());
            assert!(inserted, "{name} was enumerated twice");
        }
    }
    names
}

fn expected_source() -> Vec<u8> {
    required_fixture(EXPECTED_REL)
}

fn trimmed(bytes: &[u8]) -> &[u8] {
    let mut end: usize = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &bytes[..end]
}

fn grade_source_match(
    fixture: &str,
    recovered: &str,
    expected: &[u8],
    pinned: SourceMatch,
) -> Result<(), String> {
    let got: &[u8] = recovered.as_bytes();
    match pinned {
        SourceMatch::Exact => (got == expected).then_some(()).ok_or_else(|| {
            format!(
                "{fixture}: recovery is pinned to reproduce EXPECTED.txt byte for byte, and it no \
                 longer does.\n--- expected ---\n{}\n--- recovered ---\n{recovered}",
                String::from_utf8_lossy(expected)
            )
        }),
        SourceMatch::ExactModuloTrailingNewline => (trimmed(got) == trimmed(expected))
            .then_some(())
            .ok_or_else(|| {
                format!(
                    "{fixture}: recovery is pinned to reproduce EXPECTED.txt byte for byte apart \
                     from trailing newlines, and it no longer does.\n--- expected ---\n{}\n--- \
                     recovered ---\n{recovered}",
                    String::from_utf8_lossy(expected)
                )
            }),
        SourceMatch::Reformatted => {
            let lowered: String = recovered.to_ascii_lowercase();
            if lowered.contains("goto ") {
                return Err(format!(
                    "{fixture}: goto scrambling survived peel and deflatten; got:\n{recovered}"
                ));
            }
            for needle in ["function greet", "return 'hello '"] {
                if !recovered.contains(needle) {
                    return Err(format!(
                        "{fixture}: the reformatted recovery lost `{needle}`; got:\n{recovered}"
                    ));
                }
            }
            Ok(())
        }
        SourceMatch::PlainPassthrough => {
            let mut want: Vec<u8> = b"<?php\n".to_vec();
            want.extend_from_slice(expected);
            (got == want.as_slice()).then_some(()).ok_or_else(|| {
                format!(
                    "{fixture}: a clean file must pass through as its own bytes, so the recovery \
                     must equal the open tag followed by EXPECTED.txt; got:\n{recovered}"
                )
            })
        }
        SourceMatch::NoBodyRecovered => {
            if recovered.contains("function greet") {
                return Err(format!(
                    "{fixture}: the eval key is read from $_GET and is not present in the file, so \
                     no run can recover the body; a recovery that prints one fabricated it; \
                     got:\n{recovered}"
                ));
            }
            let residual: Vec<&'static str> = residual_decode_primitives(recovered);
            if !residual.contains(&"eval(") {
                return Err(format!(
                    "{fixture}: the unrecoverable loader must be handed back with its \
                     runtime-keyed eval intact so a reader can see what was not peeled; \
                     got:\n{recovered}"
                ));
            }
            Ok(())
        }
    }
}

fn grade_behavior(
    php: &PhpRuntime,
    fixture: &str,
    recovered: &str,
    expected_stdout: &[u8],
    pinned: Behavior,
) -> Result<(), String> {
    let run: PhpRun = php.run(fixture, with_open_tag(recovered).as_bytes());
    match pinned {
        Behavior::MatchesOriginal => {
            if !run.exited_clean {
                return Err(format!(
                    "{fixture}: the recovered source does not run under php (stderr `{}`), so it \
                     cannot be the program that was obfuscated:\n{recovered}",
                    run.stderr
                ));
            }
            if run.stdout != expected_stdout {
                return Err(format!(
                    "{fixture}: the recovered source runs but prints {:?} where the original \
                     prints {:?}\n--- recovered ---\n{recovered}",
                    String::from_utf8_lossy(&run.stdout),
                    String::from_utf8_lossy(expected_stdout)
                ));
            }
            let residual: Vec<&'static str> = residual_decode_primitives(recovered);
            if !residual.is_empty() {
                return Err(format!(
                    "{fixture}: the recovered source runs to the right output but still calls \
                     {residual:?}, so a layer was left unpeeled; a partly peeled loader executes \
                     identically and must not pass as recovered source:\n{recovered}"
                ));
            }
            Ok(())
        }
        Behavior::WalledWithoutFabricating => {
            if run.exited_clean && run.stdout == expected_stdout {
                return Err(format!(
                    "{fixture}: this loader takes its key from $_GET, so nothing recovered from \
                     the file alone can reproduce the original output; a run that does means the \
                     body was fabricated:\n{recovered}"
                ));
            }
            Ok(())
        }
    }
}

fn grade_fixture(
    php: &PhpRuntime,
    golden: &Golden,
    expected: &[u8],
    expected_stdout: &[u8],
) -> Vec<String> {
    let bytes: Vec<u8> = required_fixture(&format!("php_real_chains/{}", golden.fixture));
    let report: RecoveryReport = recover_php(&bytes, None).unwrap_or_else(|err| {
        panic!(
            "{}: recovery returned an error, so this fixture graded nothing: {err}",
            golden.fixture
        )
    });
    let mut defects: Vec<String> = Vec::new();
    if report.stage != golden.stage {
        defects.push(format!(
            "{}: pinned to reach {:?}, reached {:?}; notes {:?}",
            golden.fixture, golden.stage, report.stage, report.notes
        ));
    }
    if let Err(defect) = grade_source_match(
        golden.fixture,
        &report.output,
        expected,
        golden.source_match,
    ) {
        defects.push(defect);
    }
    if let Err(defect) = grade_behavior(
        php,
        golden.fixture,
        &report.output,
        expected_stdout,
        golden.behavior,
    ) {
        defects.push(defect);
    }
    defects
}

#[test]
fn every_committed_chain_fixture_is_pinned_by_name() {
    let on_disk: BTreeSet<String> = fixtures_on_disk();
    let pinned: BTreeSet<String> = GOLDEN
        .iter()
        .map(|golden: &Golden| golden.fixture.to_owned())
        .collect();
    assert_eq!(
        pinned.len(),
        GOLDEN.len(),
        "the golden table names the same fixture twice, so one row grades nothing"
    );
    let ungraded: Vec<&String> = on_disk.difference(&pinned).collect();
    assert!(
        ungraded.is_empty(),
        "these chain fixtures are committed but graded by nothing: {ungraded:?}. A corpus that \
         grows without its golden growing lets a family be added and never measured."
    );
    let missing: Vec<&String> = pinned.difference(&on_disk).collect();
    assert!(
        missing.is_empty(),
        "these fixtures are pinned in the golden but absent from the corpus: {missing:?}. Deleting \
         an input must fail rather than quietly shrink what recovery is measured over."
    );
    assert_eq!(
        on_disk.len(),
        GOLDEN.len(),
        "the chain corpus holds {} files and the golden pins {}; the total is asserted separately \
         from the names so trading one fixture for another cannot keep the count looking right",
        on_disk.len(),
        GOLDEN.len()
    );
}

#[test]
fn every_chain_fixture_recovers_to_the_original_source_and_runs_like_it() {
    let Some(php): Option<PhpRuntime> = require_php(GRADED) else {
        return;
    };
    let expected: Vec<u8> = expected_source();
    let expected_stdout: Vec<u8> = php.stdout_of(
        "EXPECTED.txt",
        with_open_tag(&String::from_utf8_lossy(&expected)).as_bytes(),
    );
    assert!(
        !expected_stdout.is_empty(),
        "the ground-truth program prints nothing under {}, so comparing stdout against it would \
         accept any recovery that also prints nothing",
        php.banner
    );
    println!(
        "grading {GRADED} against {}; ground truth prints {:?}",
        php.banner,
        String::from_utf8_lossy(&expected_stdout)
    );

    let mut defects: Vec<String> = Vec::new();
    let mut graded: usize = 0;
    for golden in &GOLDEN {
        defects.extend(grade_fixture(&php, golden, &expected, &expected_stdout));
        graded += 1;
    }
    assert_eq!(
        graded,
        GOLDEN.len(),
        "every pinned fixture must be measured, not skipped"
    );
    assert!(
        defects.is_empty(),
        "{} pinned grades failed across {graded} chain fixtures:\n\n{}",
        defects.len(),
        defects.join("\n\n")
    );
    println!("{graded} chain fixtures graded, each at its pinned strength");
}

fn message_from_seeded_defect(what: &str, check: impl FnOnce() + UnwindSafe) -> String {
    eprintln!("seeding a defect ({what}); the failure below is the expected outcome");
    let outcome: std::thread::Result<()> = std::panic::catch_unwind(check);
    let payload: Box<dyn Any + Send> = outcome.expect_err(
        "a seeded defect must make this grade fail; a check that accepts a corrupted recovery pins \
         nothing",
    );
    let owned: Option<String> = payload.downcast_ref::<String>().cloned();
    owned
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message: &&str| (*message).to_owned())
        })
        .unwrap_or_else(|| panic!("the failure must carry a message naming what regressed"))
}

#[test]
fn the_chain_grade_rejects_a_corrupted_body_a_left_over_layer_and_a_fabricated_wall() {
    let Some(php): Option<PhpRuntime> = require_php(GRADED) else {
        return;
    };
    let expected: Vec<u8> = expected_source();
    let expected_stdout: Vec<u8> = php.stdout_of(
        "EXPECTED.txt",
        with_open_tag(&String::from_utf8_lossy(&expected)).as_bytes(),
    );
    let truth: String = String::from_utf8_lossy(&expected).into_owned();

    grade_source_match("control", &truth, &expected, SourceMatch::Exact)
        .expect("the untouched ground truth must satisfy the exact grade");
    grade_behavior(
        &php,
        "control",
        &truth,
        &expected_stdout,
        Behavior::MatchesOriginal,
    )
    .expect("the untouched ground truth must satisfy the behavioral grade");

    let corrupted: String = truth.replace("hello ", "goodbye ");
    assert!(
        grade_source_match("corrupted", &corrupted, &expected, SourceMatch::Exact).is_err(),
        "a body whose string literal changed must be rejected on bytes"
    );
    let corrupted_defect: String =
        message_from_seeded_defect("one changed string literal in the recovered body", || {
            grade_behavior(
                &php,
                "corrupted",
                &corrupted,
                &expected_stdout,
                Behavior::MatchesOriginal,
            )
            .unwrap_or_else(|defect: String| panic!("{defect}"));
        });
    assert!(
        corrupted_defect.contains("prints"),
        "a recovery that runs but prints the wrong thing must be reported as a behavioral \
         divergence, got: {corrupted_defect}"
    );

    let under_peeled: String = format!("{truth}\n$unused = base64_decode('aGVsbG8=');\n");
    let residual_defect: String = message_from_seeded_defect(
        "a decode primitive left in a recovery that still prints the right output",
        || {
            grade_behavior(
                &php,
                "under-peeled",
                &under_peeled,
                &expected_stdout,
                Behavior::MatchesOriginal,
            )
            .unwrap_or_else(|defect: String| panic!("{defect}"));
        },
    );
    assert!(
        residual_defect.contains("unpeeled"),
        "a recovery that executes correctly while still calling a decoder must be rejected as \
         partly peeled, got: {residual_defect}"
    );

    let fabricated_defect: String = message_from_seeded_defect(
        "a body invented for a loader whose key never appears in the file",
        || {
            grade_behavior(
                &php,
                "fabricated-wall",
                &truth,
                &expected_stdout,
                Behavior::WalledWithoutFabricating,
            )
            .unwrap_or_else(|defect: String| panic!("{defect}"));
        },
    );
    assert!(
        fabricated_defect.contains("fabricated"),
        "producing the original output for a runtime-keyed loader must be rejected as fabrication, \
         got: {fabricated_defect}"
    );

    assert!(
        grade_source_match(
            "fabricated-wall",
            &truth,
            &expected,
            SourceMatch::NoBodyRecovered
        )
        .is_err(),
        "a wall that hands back the recovered body must be rejected"
    );
}
