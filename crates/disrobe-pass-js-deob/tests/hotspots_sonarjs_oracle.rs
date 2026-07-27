#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_js_deob::{
    HotspotConfig, HotspotFinding, HotspotRule, analyze_hotspots, analyze_hotspots_with,
};

const ANNOTATED_FIXTURES: &[&str] = &[
    "dynamic_code.js",
    "weak_crypto.js",
    "insecure_tls.js",
    "cookies.js",
    "dom_xss.js",
];

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("hotspots")
}

fn read_fixture(name: &str) -> String {
    fs::read_to_string(fixtures_dir().join(name)).unwrap_or_else(|_| panic!("read fixture {name}"))
}

fn parse_annotations(source: &str) -> BTreeMap<u32, BTreeSet<String>> {
    let mut expected: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for (idx, line) in source.lines().enumerate() {
        let Some(marker): Option<usize> = line.find("// Noncompliant") else {
            continue;
        };
        let lineno: u32 = u32::try_from(idx + 1).unwrap();
        let mut ids: BTreeSet<String> = BTreeSet::new();
        let mut rest: &str = &line[marker..];
        while let Some(open) = rest.find("{{") {
            let after: &str = &rest[open + 2..];
            let Some(close): Option<usize> = after.find("}}") else {
                break;
            };
            let token: &str = after[..close].trim();
            if !token.is_empty() {
                ids.insert(token.to_owned());
            }
            rest = &after[close + 2..];
        }
        expected.insert(lineno, ids);
    }
    expected
}

fn index_findings(findings: &[HotspotFinding]) -> (BTreeSet<u32>, BTreeMap<u32, BTreeSet<String>>) {
    let mut flagged: BTreeSet<u32> = BTreeSet::new();
    let mut per_line: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for finding in findings {
        flagged.insert(finding.line);
        per_line
            .entry(finding.line)
            .or_default()
            .insert(finding.rule_id.to_owned());
    }
    (flagged, per_line)
}

fn grade_fixture(name: &str) {
    let source: String = read_fixture(name);
    let expected: BTreeMap<u32, BTreeSet<String>> = parse_annotations(&source);
    assert!(
        !expected.is_empty(),
        "{name} must carry at least one Noncompliant annotation"
    );
    let findings: Vec<HotspotFinding> = analyze_hotspots(&source);
    let (flagged, per_line): (BTreeSet<u32>, BTreeMap<u32, BTreeSet<String>>) =
        index_findings(&findings);
    let expected_lines: BTreeSet<u32> = expected.keys().copied().collect();

    for (line, ids) in &expected {
        assert!(
            flagged.contains(line),
            "recall miss: {name}:{line} is annotated Noncompliant but disrobe flagged nothing\nfindings={findings:?}"
        );
        if !ids.is_empty() {
            let got: BTreeSet<String> = per_line.get(line).cloned().unwrap_or_default();
            assert_eq!(
                &got, ids,
                "rule-id mismatch at {name}:{line}: expected {ids:?}, got {got:?}"
            );
        }
    }

    for line in &flagged {
        assert!(
            expected_lines.contains(line),
            "precision miss (false positive): {name}:{line} was flagged {:?} but is a clean line",
            per_line.get(line)
        );
    }

    let hits: usize = expected
        .keys()
        .filter(|line| flagged.contains(line))
        .count();
    println!(
        "[{name}] recall {hits}/{} lines, precision {}/{} flagged lines on annotated set",
        expected.len(),
        flagged
            .iter()
            .filter(|l| expected_lines.contains(l))
            .count(),
        flagged.len()
    );
}

#[test]
fn dynamic_code_matches_annotations() {
    grade_fixture("dynamic_code.js");
}

#[test]
fn weak_crypto_matches_annotations() {
    grade_fixture("weak_crypto.js");
}

#[test]
fn insecure_tls_matches_annotations() {
    grade_fixture("insecure_tls.js");
}

#[test]
fn cookies_match_annotations() {
    grade_fixture("cookies.js");
}

#[test]
fn dom_xss_matches_annotations() {
    grade_fixture("dom_xss.js");
}

#[test]
fn clean_fixture_produces_zero_findings() {
    let source: String = read_fixture("clean.js");
    assert!(
        !source.contains("Noncompliant"),
        "the clean fixture must not carry any Noncompliant marker"
    );
    let findings: Vec<HotspotFinding> = analyze_hotspots(&source);
    assert!(
        findings.is_empty(),
        "the clean fixture must yield zero findings; got {findings:?}"
    );
}

#[test]
fn disabling_each_rule_removes_exactly_its_findings() {
    let sources: Vec<String> = ANNOTATED_FIXTURES.iter().map(|n| read_fixture(n)).collect();
    for rule in HotspotRule::all() {
        let mut exercised: usize = 0;
        for src in &sources {
            let full: Vec<HotspotFinding> = analyze_hotspots(src);
            let reduced: Vec<HotspotFinding> =
                analyze_hotspots_with(src, &HotspotConfig::all().without(rule));
            assert!(
                reduced.iter().all(|f| f.rule != rule),
                "disabling {rule:?} still emitted a {rule:?} finding"
            );
            let survivors: Vec<&HotspotFinding> = full.iter().filter(|f| f.rule != rule).collect();
            assert_eq!(
                reduced.len(),
                survivors.len(),
                "disabling {rule:?} must remove only its own findings, not touch the rest"
            );
            for (left, right) in reduced.iter().zip(survivors.iter()) {
                assert_eq!(
                    &left, right,
                    "disabling {rule:?} perturbed a sibling finding"
                );
            }
            exercised += full.iter().filter(|f| f.rule == rule).count();
        }
        assert!(
            exercised > 0,
            "rule {rule:?} fires on no fixture line; the matcher is never exercised"
        );
    }
}

#[test]
fn every_rule_maps_to_a_distinct_sonar_id() {
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for rule in HotspotRule::all() {
        assert!(
            rule.sonar_id().starts_with('S'),
            "{rule:?} sonar id must look like a Sonar rule key"
        );
        assert!(
            seen.insert(rule.sonar_id()),
            "duplicate sonar id for {rule:?}"
        );
    }
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn eslint_available() -> bool {
    Command::new("node")
        .arg("-e")
        .arg("require.resolve('eslint')")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn eslint_flagged_lines(fixture_source: &str) -> Option<BTreeSet<u32>> {
    let script: &str = r"
const { Linter } = require('eslint');
const fs = require('fs');
const code = fs.readFileSync(process.argv[1], 'utf8');
const linter = new Linter();
const messages = linter.verify(code, {
  languageOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    globals: {
      setTimeout: 'readonly',
      setInterval: 'readonly',
      Function: 'readonly',
      window: 'readonly',
      globalThis: 'readonly',
      JSON: 'readonly',
    },
  },
  rules: { 'no-eval': 'error', 'no-implied-eval': 'error', 'no-new-func': 'error' },
});
process.stdout.write(JSON.stringify(messages.map((m) => m.line)));
";
    let (scratch, mut f): (disrobe_core::scratch::ScratchFile, fs::File) =
        disrobe_core::scratch::ScratchFile::create("disrobe_hotspot", "js").ok()?;
    let src_path: PathBuf = scratch.path().to_path_buf();
    f.write_all(fixture_source.as_bytes()).ok()?;
    drop(f);
    let output: std::process::Output = Command::new("node")
        .arg("-e")
        .arg(script)
        .arg(&src_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8(output.stdout).ok()?;
    let lines: Vec<u32> = serde_json::from_str(&raw).ok()?;
    Some(lines.into_iter().collect())
}

#[test]
fn differential_against_real_eslint_dynamic_code() {
    if !node_available() || !eslint_available() {
        println!("[differential] node/eslint absent, skipped");
        return;
    }
    let source: String = read_fixture("dynamic_code.js");
    let Some(eslint_lines): Option<BTreeSet<u32>> = eslint_flagged_lines(&source) else {
        println!("[differential] eslint invocation failed, skipped");
        return;
    };
    let findings: Vec<HotspotFinding> = analyze_hotspots(&source);
    let disrobe_lines: BTreeSet<u32> = findings
        .iter()
        .filter(|f| f.rule == HotspotRule::DynamicCodeExecution)
        .map(|f| f.line)
        .collect();
    assert_eq!(
        disrobe_lines, eslint_lines,
        "differential: disrobe S1523 lines must match real eslint (no-eval + no-implied-eval + no-new-func); disrobe={disrobe_lines:?} eslint={eslint_lines:?}"
    );
    println!(
        "[differential] disrobe S1523 lines match real eslint exactly: {} eval-family lines",
        eslint_lines.len()
    );
}
