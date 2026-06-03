#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

use std::path::{Path, PathBuf};

use disrobe_playground::circular::{CircularityKind, CircularityReport};
use disrobe_playground::manifest::ManifestIndex;
use disrobe_playground::oracle::{OracleResult, OracleVerdict, ResolvedFixture};
use disrobe_playground::report::{PlaygroundReport, render_json};
use disrobe_playground::{OracleKind, Runner, RunnerConfig, scan_circularity};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_root() -> PathBuf {
    workspace_root().join("corpus")
}

fn cli_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn canary_dir() -> PathBuf {
    cli_tests_dir().join("_circular_canary")
}

fn real_tree_scan_roots() -> Vec<PathBuf> {
    vec![corpus_root(), cli_tests_dir().join("chain")]
}

#[test]
fn circular_detector_reports_real_tree_clean() {
    let report: CircularityReport = scan_circularity(&real_tree_scan_roots());
    assert!(
        report.is_clean(),
        "PRIME DIRECTIVE VIOLATION: circularity detector found {} self-referential oracle(s) in the real tree (count must be 0): {:#?}",
        report.count(),
        report.findings,
    );
    assert_eq!(
        report.count(),
        0,
        "real-tree circularity count must be exactly 0"
    );
    assert!(
        report.files_scanned > 0,
        "detector scanned zero golden/oracle files - scan roots are wrong",
    );
}

#[test]
fn circular_detector_trips_the_planted_canary() {
    let canary: PathBuf = canary_dir();
    assert!(
        canary.is_dir(),
        "planted canary directory missing at {}",
        canary.display(),
    );
    let report: CircularityReport = scan_circularity(&[canary]);
    assert!(
        !report.is_clean(),
        "ANTI-GAMING-THE-ANTI-GAMING FAILURE: the detector did NOT flag the deliberately circular canary. A detector that cannot detect a planted circular oracle is worthless.",
    );
    assert!(
        report.count() >= 1,
        "canary must produce at least one circularity finding, got {}",
        report.count(),
    );
    let trips_self_emit: bool = report.findings.iter().any(|f| {
        matches!(
            f.kind,
            CircularityKind::PassOutputEqualsOwnGolden
                | CircularityKind::SelfEmittedGolden
                | CircularityKind::ProvenanceSelfReference
        )
    });
    assert!(
        trips_self_emit,
        "canary must trip a self-emission/self-reference finding kind; got: {:#?}",
        report.findings,
    );
}

#[test]
fn detector_distinguishes_canary_from_real_tree() {
    let real: CircularityReport = scan_circularity(&real_tree_scan_roots());
    let canary: CircularityReport = scan_circularity(&[canary_dir()]);
    assert_eq!(real.count(), 0, "real tree must be clean");
    assert!(canary.count() >= 1, "canary must be flagged");
    assert!(
        canary.count() > real.count(),
        "detector must flag strictly more circularity in the canary ({}) than the real tree ({})",
        canary.count(),
        real.count(),
    );
}

fn build_sample() -> Vec<ResolvedFixture> {
    let index: ManifestIndex = ManifestIndex::build(&corpus_root());
    let resolved: Vec<ResolvedFixture> = index.resolve(&corpus_root());
    let mut sample: Vec<ResolvedFixture> = Vec::new();

    push_named(&resolved, &mut sample, "decompile:tiny_3_14_cpython_314");
    push_named(&resolved, &mut sample, "decompile:tiny2_3_14_cpython_314");
    push_named(&resolved, &mut sample, "upx:hello");

    for kind in OracleKind::all() {
        let take_n: usize = match kind {
            OracleKind::RecompileEquiv | OracleKind::ByteIdenticalUnpack => 3,
            OracleKind::DifferentialVsSource | OracleKind::DetectionDeterministic => 2,
        };
        let picked: Vec<ResolvedFixture> = resolved
            .iter()
            .filter(|f| f.oracle == kind && !sample.iter().any(|s| s.fixture_id == f.fixture_id))
            .take(take_n)
            .cloned()
            .collect();
        sample.extend(picked);
    }
    sample
}

fn push_named(resolved: &[ResolvedFixture], sample: &mut Vec<ResolvedFixture>, id: &str) {
    if let Some(fx) = resolved.iter().find(|f| f.fixture_id == id) {
        sample.push(fx.clone());
    }
}

fn run_sample(sample: &[ResolvedFixture]) -> Vec<OracleResult> {
    let runner: Runner = Runner::new(RunnerConfig::default());
    sample
        .iter()
        .map(|fx: &ResolvedFixture| OracleResult {
            oracle: fx.oracle,
            pass_under_test: fx.pass_under_test.clone(),
            fixture_id: fx.fixture_id.clone(),
            input_rel: fx.input_rel.clone(),
            baseline_rel: fx.baseline_rel.clone(),
            verdict: runner.evaluate(fx),
        })
        .collect()
}

#[test]
fn manifest_index_resolves_all_four_oracle_kinds() {
    let index: ManifestIndex = ManifestIndex::build(&corpus_root());
    assert!(
        index.manifests_parsed() > 0,
        "expected to parse at least one MANIFEST.toml",
    );
    for kind in OracleKind::all() {
        let n: usize = index.by_kind(kind).len();
        assert!(
            n > 0,
            "oracle kind {} resolved zero fixtures - the manifest pairings for it are missing",
            kind.label(),
        );
    }
}

#[test]
fn reporter_emits_per_oracle_kind_vector_with_skips_excluded() {
    let sample: Vec<ResolvedFixture> = build_sample();
    let results: Vec<OracleResult> = run_sample(&sample);

    for r in &results {
        if let OracleVerdict::ToolMissing { tool } = &r.verdict {
            eprintln!(
                "SKIP (excluded from denominator) {} :: {tool}",
                r.fixture_id
            );
        }
        if let OracleVerdict::FixtureAbsent { rel } = &r.verdict {
            eprintln!("SKIP (fixture absent) {} :: {rel}", r.fixture_id);
        }
    }

    let circ: CircularityReport = scan_circularity(&real_tree_scan_roots());
    let report: PlaygroundReport = PlaygroundReport::from_results(results, circ.count(), 1);

    assert_eq!(
        report.rows.len(),
        4,
        "headline must be a VECTOR of exactly 4 per-oracle-kind rows, never a single percentage",
    );

    for row in &report.rows {
        let skips: u32 = row.tool_missing + row.fixture_absent;
        let observed_total: u32 = row.recovered + row.lossy + row.no_recovery + row.pass_error;
        assert_eq!(
            row.evaluated,
            observed_total,
            "oracle {} denominator ({}) must equal sum of in-denominator verdicts ({}); SKIPs ({}) excluded",
            row.oracle.label(),
            row.evaluated,
            observed_total,
            skips,
        );
        assert!(
            row.recovery_bp() <= 10_000,
            "recovery basis-points must be bounded",
        );
        if row.lossy > 0 || row.no_recovery > 0 || row.pass_error > 0 {
            assert!(
                row.recovery_bp() < 10_000,
                "oracle {} has lossy/failed fixtures but reports 100.00% - lossy residuals must never round up to 100",
                row.oracle.label(),
            );
        }
        eprintln!(
            "ORACLE {:<24} recovered={} byte_identical={} detect_correct={} lossy={} no_recovery={} pass_error={} tool_missing={} fixture_absent={} ceiling_residual_bp={} -> {:.2}%",
            row.oracle.label(),
            row.recovered,
            row.byte_identical,
            row.detect_correct,
            row.lossy,
            row.no_recovery,
            row.pass_error,
            row.tool_missing,
            row.fixture_absent,
            row.ceiling_residual_bp,
            f64::from(row.recovery_bp()) / 100.0,
        );
    }
}

#[test]
fn detection_oracle_floor_holds() {
    let sample: Vec<ResolvedFixture> = build_sample();
    let results: Vec<OracleResult> = run_sample(&sample);
    let circ: CircularityReport = scan_circularity(&real_tree_scan_roots());
    let report: PlaygroundReport = PlaygroundReport::from_results(results, circ.count(), 1);
    let det = report
        .row(OracleKind::DetectionDeterministic)
        .expect("detection row present");
    assert!(
        det.evaluated > 0,
        "detection oracle must evaluate at least one fixture",
    );
    assert_eq!(
        det.detect_correct, det.evaluated,
        "every sampled detection fixture must classify to its manifest-declared label (deterministic floor 100%)",
    );
}

#[test]
fn differential_oracle_recovers_obfuscated_python() {
    let sample: Vec<ResolvedFixture> = build_sample();
    let results: Vec<OracleResult> = run_sample(&sample);
    let circ: CircularityReport = scan_circularity(&real_tree_scan_roots());
    let report: PlaygroundReport = PlaygroundReport::from_results(results, circ.count(), 1);
    let diff = report
        .row(OracleKind::DifferentialVsSource)
        .expect("differential row present");
    assert!(
        diff.evaluated > 0,
        "differential oracle must evaluate fixtures"
    );
    assert_eq!(
        diff.recovered, diff.evaluated,
        "sampled obfuscated-python fixtures must each recover a non-empty normalized token stream",
    );
}

#[test]
fn recompile_oracle_proves_at_least_one_construct_recompiles_equivalent() {
    let sample: Vec<ResolvedFixture> = build_sample();
    let results: Vec<OracleResult> = run_sample(&sample);
    let recompile: Vec<&OracleResult> = results
        .iter()
        .filter(|r| r.oracle == OracleKind::RecompileEquiv)
        .collect();
    let evaluated: usize = recompile
        .iter()
        .filter(|r| r.verdict.counts_in_denominator())
        .count();
    if evaluated == 0 {
        eprintln!("SKIP: no version-matched interpreter on PATH for any recompile fixture");
        return;
    }
    let recovered: usize = recompile
        .iter()
        .filter(|r| matches!(r.verdict, OracleVerdict::Recovered))
        .count();
    assert!(
        recovered >= 1,
        "with a version-matched interpreter present, at least one py construct must recompile-equivalent (independent recompile oracle); evaluated={evaluated}, recovered={recovered}",
    );
}

#[test]
fn byte_identical_oracle_proves_a_cryptographically_verified_unpack() {
    let sample: Vec<ResolvedFixture> = build_sample();
    let results: Vec<OracleResult> = run_sample(&sample);
    let upx: Option<&OracleResult> = results.iter().find(|r| r.fixture_id == "upx:hello");
    let Some(upx): Option<&OracleResult> = upx else {
        eprintln!("SKIP: committed upx:hello fixture not present");
        return;
    };
    assert!(
        matches!(upx.verdict, OracleVerdict::ByteIdentical),
        "upx:hello must recover byte-identical (UCL adler32 cryptographic witness embedded by the real upx tool, independent of disrobe); got {:?}",
        upx.verdict,
    );
}

#[test]
fn playground_report_is_byte_identical_across_two_in_process_runs() {
    let sample: Vec<ResolvedFixture> = build_sample();
    let circ: usize = scan_circularity(&real_tree_scan_roots()).count();

    let first: PlaygroundReport = PlaygroundReport::from_results(run_sample(&sample), circ, 1);
    let second: PlaygroundReport = PlaygroundReport::from_results(run_sample(&sample), circ, 1);

    let a: String = canonicalize(&first);
    let b: String = canonicalize(&second);
    assert_eq!(
        a, b,
        "playground report must be byte-identical across two in-process runs (determinism)",
    );
}

fn canonicalize(report: &PlaygroundReport) -> String {
    let json: String = render_json(report);
    json.replace("\r\n", "\n")
}

#[test]
fn byte_identical_oracle_has_at_least_one_real_unpacker_route() {
    let index: ManifestIndex = ManifestIndex::build(&corpus_root());
    let routed: bool = index
        .by_kind(OracleKind::ByteIdenticalUnpack)
        .iter()
        .any(|f| {
            f.fixture_id.starts_with("upx:")
                || f.fixture_id.starts_with("fsg:")
                || f.fixture_id.starts_with("mew:")
        });
    assert!(
        routed,
        "byte-identical oracle must route at least one upx/fsg/mew fixture to a real clean-room unpacker",
    );
}

fn _assert_paths_absolute() {
    let _: &Path = workspace_root().as_path();
}
