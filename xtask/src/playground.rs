use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use disrobe_playground::oracle::{OracleResult, ResolvedFixture};
use disrobe_playground::{
    CircularityReport, ManifestIndex, OracleKind, OracleVerdict, PlaygroundReport, Runner,
    RunnerConfig, render_json, render_tsv, scan_circularity,
};

pub(crate) struct PlaygroundOptions {
    pub(crate) sample_per_kind: Option<usize>,
    pub(crate) fail_under_circularity: bool,
}

pub(crate) fn run(workspace_root: &Path, opts: &PlaygroundOptions) -> Result<()> {
    let corpus_root: PathBuf = workspace_root.join("corpus");
    if !corpus_root.is_dir() {
        bail!("corpus dir missing: {}", corpus_root.display());
    }

    let index: ManifestIndex = ManifestIndex::build(&corpus_root);
    println!(
        "xtask playground: parsed {} MANIFEST.toml file(s), resolved {} oracle fixture(s)",
        index.manifests_parsed(),
        index.fixtures().len(),
    );

    let resolved: Vec<ResolvedFixture> = index.resolve(&corpus_root);
    let selected: Vec<ResolvedFixture> = match opts.sample_per_kind {
        Some(n) => sample_per_kind(&resolved, n),
        None => resolved,
    };

    let runner: Runner = Runner::new(RunnerConfig::default());
    let mut results: Vec<OracleResult> = Vec::with_capacity(selected.len());
    for fx in &selected {
        let verdict: OracleVerdict = runner.evaluate(fx);
        results.push(OracleResult {
            oracle: fx.oracle,
            pass_under_test: fx.pass_under_test.clone(),
            fixture_id: fx.fixture_id.clone(),
            input_rel: fx.input_rel.clone(),
            baseline_rel: fx.baseline_rel.clone(),
            verdict,
        });
    }

    let circ: CircularityReport = scan_circularity(&[
        workspace_root.join("corpus"),
        workspace_root
            .join("crates")
            .join("disrobe-cli")
            .join("tests")
            .join("chain"),
    ]);
    let canary: CircularityReport = scan_circularity(&[workspace_root
        .join("crates")
        .join("disrobe-cli")
        .join("tests")
        .join("_circular_canary")]);

    let report: PlaygroundReport =
        PlaygroundReport::from_results(results, circ.count(), index.manifests_parsed());

    let out_dir: PathBuf = workspace_root.join("target").join("playground");
    fs::create_dir_all(&out_dir).with_context_msg(|| format!("creating {}", out_dir.display()))?;
    let tsv_path: PathBuf = out_dir.join("report.tsv");
    let json_path: PathBuf = out_dir.join("report.json");
    fs::write(&tsv_path, render_tsv(&report))
        .with_context_msg(|| format!("writing {}", tsv_path.display()))?;
    fs::write(&json_path, render_json(&report))
        .with_context_msg(|| format!("writing {}", json_path.display()))?;

    print_headline(&report);
    print_circularity("REAL-TREE", &circ);
    print_circularity("CANARY (must be > 0)", &canary);
    if canary.is_clean() {
        bail!(
            "anti-gaming-the-anti-gaming failure: the circularity detector did NOT flag the planted canary",
        );
    }

    println!(
        "xtask playground: wrote {} and {}",
        tsv_path.display(),
        json_path.display(),
    );

    if opts.fail_under_circularity && !circ.is_clean() {
        bail!(
            "circularity detector found {} self-referential oracle(s) in the real tree",
            circ.count(),
        );
    }
    Ok(())
}

fn sample_per_kind(resolved: &[ResolvedFixture], n: usize) -> Vec<ResolvedFixture> {
    let mut out: Vec<ResolvedFixture> = Vec::new();
    for kind in OracleKind::all() {
        let taken: Vec<ResolvedFixture> = resolved
            .iter()
            .filter(|f: &&ResolvedFixture| f.oracle == kind)
            .take(n)
            .cloned()
            .collect();
        out.extend(taken);
    }
    out
}

fn print_headline(report: &PlaygroundReport) {
    println!(
        "xtask playground: per-oracle-kind headline VECTOR (recovered/evaluated @ recovery_bp):"
    );
    for (oracle, recovered, evaluated, bp) in report.headline_vector() {
        let pct: f64 = f64::from(bp) / 100.0;
        println!(
            "  {:<24} {:>4}/{:<4} = {:>6.2}% (residual_ceiling_bp={})",
            oracle.label(),
            recovered,
            evaluated,
            pct,
            report
                .row(oracle)
                .map_or(0, |r: &disrobe_playground::OracleKindRow| {
                    r.ceiling_residual_bp
                }),
        );
    }
}

fn print_circularity(label: &str, circ: &CircularityReport) {
    println!(
        "xtask playground: circularity[{label}] scanned {} golden/oracle file(s) -> {} finding(s)",
        circ.files_scanned,
        circ.count(),
    );
    for f in &circ.findings {
        println!(
            "  CIRCULAR[{}] {} ({}): {}",
            f.kind.label(),
            f.path,
            f.pass_id.as_deref().unwrap_or("-"),
            f.evidence,
        );
    }
}

trait WithContext<T> {
    fn with_context_msg<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E> WithContext<T> for core::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_context_msg<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.wrap_err_with(f)
    }
}
