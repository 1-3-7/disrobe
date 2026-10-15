#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_js_deob::{Detection, JsObfuRecovery, JsObfuscator, detect, recover_jsobfu};
use regex::Regex;
use sha2::{Digest, Sha256};

#[path = "common/mod.rs"]
mod common;

const OBFUSCATED_SHA256: &str = "fb8a0fa445ef48d791834b971a7621c1e23a2f64480c8ee9aa07c4d33380e329";

struct AuthoredReference {
    source_sha256: &'static str,
    output: &'static str,
}

const AUTHORED_REFERENCE: AuthoredReference = AuthoredReference {
    source_sha256: "7576a69b3e0dd823087c56f5705d8b5c28d0c30a5a90a306e1b9ccca574aedfe",
    output: "{\"greeting\":\"hi world!\",\"sum\":3,\"product\":12,\"fib10\":55,\"factorial5\":120,\"count\":5,\"registered\":\"greet,add,mul,fib,factorial\"}",
};

fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> String {
    let p: PathBuf = corpus(rel);
    fs::read_to_string(&p)
        .unwrap_or_else(|error| panic!("required corpus fixture {}: {error}", p.display()))
}

fn assert_sha256(label: &str, source: &str, expected: &str) {
    let actual: String = format!("{:x}", Sha256::digest(source.as_bytes()));
    assert_eq!(actual, expected, "{label} fixture hash changed");
}

fn eval_console_output(script: &str) -> Result<String, common::BoaWorkerError> {
    let executable: PathBuf = std::env::current_exe().map_err(|error: std::io::Error| {
        common::BoaWorkerError::HarnessFailure(error.to_string())
    })?;
    common::BoaWorker::new(executable)?.eval_capture(script, &[])
}

#[test]
fn real_jsobfu_classifies_as_jsobfu_family() {
    let src: String = load("jsobfu/obfuscated.js");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(
        det.family,
        JsObfuscator::JsObfu,
        "real jsobfu ES5 output must classify as the JsObfu family, not {:?}",
        det.family
    );
    assert!(det.confidence >= 0.5, "confidence floor: {det:?}");
}

#[test]
fn clean_source_not_misclassified_as_jsobfu() {
    let src: String = load("jsobfu/input.js");
    let det: Detection = detect(src.as_bytes());
    assert_ne!(
        det.family,
        JsObfuscator::JsObfu,
        "the clean ground-truth source must not be misdetected as jsobfu"
    );
}

#[test]
fn real_jsobfu_recovery_folds_fromcharcode_chains() {
    let src: String = load("jsobfu/obfuscated.js");
    let out: JsObfuRecovery = recover_jsobfu(&src);
    assert!(
        out.char_fold.from_char_code_calls_folded >= 20,
        "recovery must statically fold many String.fromCharCode chains; got {}",
        out.char_fold.from_char_code_calls_folded
    );
    assert!(
        !out.source.contains("String.fromCharCode"),
        "no String.fromCharCode chain may survive a full recovery"
    );
}

#[test]
fn recovered_jsobfu_is_behaviorally_identical_to_ground_truth() {
    let obf: String = load("jsobfu/obfuscated.js");
    let original: String = load("jsobfu/input.js");
    assert_sha256("obfuscated", &obf, OBFUSCATED_SHA256);
    assert_sha256(
        "authored input",
        &original,
        AUTHORED_REFERENCE.source_sha256,
    );

    let out: JsObfuRecovery = recover_jsobfu(&obf);
    let recovered_output: String =
        eval_console_output(&out.source).expect("recovered jsobfu must re-parse and run under boa");

    assert_eq!(
        recovered_output, AUTHORED_REFERENCE.output,
        "recovered jsobfu must produce the pinned reference output"
    );
}

#[test]
fn recovered_jsobfu_output_mutation_is_rejected() {
    let obf: String = load("jsobfu/obfuscated.js");
    let authored: String = load("jsobfu/input.js");
    assert_sha256("obfuscated", &obf, OBFUSCATED_SHA256);
    assert_sha256(
        "authored input",
        &authored,
        AUTHORED_REFERENCE.source_sha256,
    );

    let out: JsObfuRecovery = recover_jsobfu(&obf);
    let recovered_output: String =
        eval_console_output(&out.source).expect("recovered jsobfu must re-parse and run under boa");
    assert_eq!(recovered_output, AUTHORED_REFERENCE.output);

    let mutated: String = format!("{}\nconsole.log('mutation');", out.source);
    let mutated_output: String =
        eval_console_output(&mutated).expect("mutated recovered code must produce console output");
    assert_ne!(
        mutated_output, AUTHORED_REFERENCE.output,
        "mutation control must turn the grade red"
    );
}

const NODE_TIMEOUT: Duration = Duration::from_mins(1);
const BROWSER_GLOBALS: &str = "globalThis.window = globalThis;\nglobalThis.document = {};\n";

struct CommittedFixture {
    obfuscated: &'static str,
    authored: Option<&'static str>,
    mutation: (&'static str, &'static str),
}

const COMMITTED_FIXTURES: [CommittedFixture; 2] = [
    CommittedFixture {
        obfuscated: "jsobfu/obfuscated.js",
        authored: Some("jsobfu/input.js"),
        mutation: ("'world'", "'w0rld'"),
    },
    CommittedFixture {
        obfuscated: "../src/javascript/jsobfu-sample.js",
        authored: None,
        mutation: ("1.5", "2.5"),
    },
];

struct Residue {
    label: &'static str,
    pattern: &'static str,
    witness: &'static str,
}

const JSOBFU_RESIDUES: [Residue; 6] = [
    Residue {
        label: "String.fromCharCode",
        pattern: r"String\.fromCharCode",
        witness: "String.fromCharCode(97)",
    },
    Residue {
        label: "literal length",
        pattern: r#"['"][^'"\n]*['"]\s*(\.length|\[\s*\(?\s*['"]length)"#,
        witness: "var n='abc'[('length')];",
    },
    Residue {
        label: "parenthesized string key",
        pattern: r#"\[\s*\(\s*['"]"#,
        witness: "x[('log')](1)",
    },
    Residue {
        label: "escaped string literal",
        pattern: r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-7])",
        witness: r#"var k="\x66\162";"#,
    },
    Residue {
        label: "legacy octal number",
        pattern: r"(^|[^0-9A-Za-z_$.])0[0-9]+",
        witness: "f(01*0117)",
    },
    Residue {
        label: "string fragment IIFE",
        pattern: r#"\(function\s*\(\)\s*\{\s*var\s+[A-Za-z_$][\w$]*\s*=\s*['"]"#,
        witness: "(function () { var Js='X'; return Js })()",
    },
];

fn run_node_file(path: &Path) -> String {
    let mut child: std::process::Child = Command::new("node")
        .env_remove("FORCE_COLOR")
        .env("NO_COLOR", "1")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| {
            panic!("node is required for the jsobfu re-execution grade: {error}")
        });
    let started: Instant = Instant::now();
    while child.try_wait().expect("poll node").is_none() {
        if started.elapsed() > NODE_TIMEOUT {
            child.kill().expect("stop node after the timeout");
            panic!("node exceeded {NODE_TIMEOUT:?} on {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output: std::process::Output = child.wait_with_output().expect("collect node output");
    assert!(
        output.status.success(),
        "{} failed under node: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("node stdout is UTF-8")
}

fn run_node_with_browser_globals(scratch: &ScratchDir, name: &str, script: &str) -> String {
    let path: PathBuf = scratch.path().join(name);
    fs::write(&path, format!("{BROWSER_GLOBALS}{script}")).expect("write the node program");
    run_node_file(&path)
}

#[test]
fn every_committed_jsobfu_fixture_reexecutes_identically_under_node() {
    let scratch: ScratchDir = ScratchDir::create("disrobe-jsobfu-reexec").expect("scratch");
    let residues: Vec<(&str, Regex)> = JSOBFU_RESIDUES
        .iter()
        .map(|residue: &Residue| {
            let pattern: Regex = Regex::new(residue.pattern).expect("residue pattern");
            assert!(
                pattern.is_match(residue.witness),
                "the {} check must fire on its witness",
                residue.label
            );
            (residue.label, pattern)
        })
        .collect();
    for (index, fixture) in COMMITTED_FIXTURES.iter().enumerate() {
        let obfuscated: String = load(fixture.obfuscated);
        let recovered: JsObfuRecovery = recover_jsobfu(&obfuscated);
        assert_ne!(recovered.source, obfuscated, "{}", fixture.obfuscated);

        let reference: String =
            run_node_with_browser_globals(&scratch, &format!("obf{index}.js"), &obfuscated);
        assert!(
            !reference.is_empty(),
            "{} prints nothing",
            fixture.obfuscated
        );
        if let Some(authored) = fixture.authored {
            assert_eq!(
                run_node_file(&corpus(authored)),
                reference,
                "{} must behave like its authored original under node",
                fixture.obfuscated
            );
        }
        assert_eq!(
            run_node_with_browser_globals(&scratch, &format!("rec{index}.js"), &recovered.source),
            reference,
            "{}: the recovered program must print what the obfuscated one prints\n{}",
            fixture.obfuscated,
            recovered.source
        );
        for (label, pattern) in &residues {
            assert!(
                !pattern.is_match(&recovered.source),
                "{}: {label} survives recovery\n{}",
                fixture.obfuscated,
                recovered.source
            );
        }

        let (from, to): (&str, &str) = fixture.mutation;
        assert!(
            recovered.source.contains(from),
            "{}: the recovered program must spell {from} as a plain literal\n{}",
            fixture.obfuscated,
            recovered.source
        );
        let mutated: String = recovered.source.replacen(from, to, 1);
        assert_ne!(
            run_node_with_browser_globals(&scratch, &format!("mut{index}.js"), &mutated),
            reference,
            "{}: a changed literal must turn the re-execution grade red",
            fixture.obfuscated
        );
    }
}
