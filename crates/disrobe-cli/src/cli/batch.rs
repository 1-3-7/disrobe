#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use walkdir::{DirEntry, WalkDir};

use super::chain_v1::{self, ChainOutcome};
use super::glob::GlobMatcher;
use super::output::{OutputFormat, emit};
use super::progress_ui::{self, ActiveProgress};
use disrobe_core::progress::Progress as _;

#[derive(Clone, Debug)]
pub(crate) struct BatchOptions {
    pub(crate) out_root: PathBuf,
    pub(crate) chain_arg: String,
    pub(crate) max_depth: Option<usize>,
    pub(crate) include: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) jobs: usize,
    pub(crate) capture_stages: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ManifestEntry {
    pub(crate) input: String,
    pub(crate) relative: String,
    pub(crate) size: u64,
    pub(crate) detected_format: Option<String>,
    pub(crate) chain: Vec<String>,
    pub(crate) verdict: Option<String>,
    pub(crate) recovery_score: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) anti_analysis: Vec<String>,
    pub(crate) output_dir: Option<String>,
    pub(crate) duration_ms: u128,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub(crate) struct BatchSummary {
    pub(crate) processed: usize,
    pub(crate) recovered: usize,
    pub(crate) detect_only: usize,
    pub(crate) errors: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BatchManifest {
    pub(crate) schema: String,
    pub(crate) tool_version: String,
    pub(crate) root: String,
    pub(crate) out_root: String,
    pub(crate) chain: String,
    pub(crate) jobs: usize,
    pub(crate) summary: BatchSummary,
    pub(crate) entries: Vec<ManifestEntry>,
}

pub(crate) const MANIFEST_SCHEMA_VERSION: &str = "disrobe.batch.manifest/v1";

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .is_some_and(|s: &str| s.len() > 1 && s.starts_with('.'))
}

fn relative_stem(relative: &Path) -> String {
    let raw: String = relative.to_string_lossy().into_owned();
    let mut slug: String = raw
        .chars()
        .map(|c: char| match c {
            '/' | '\\' | ':' => '-',
            other => other,
        })
        .collect();
    if let Some(stripped) = slug.strip_suffix('-') {
        slug = stripped.to_string();
    }
    if slug.is_empty() {
        "file".to_string()
    } else {
        slug
    }
}

fn recovery_score(report: &disrobe_core::chain::ChainRecoveryReport) -> Option<f64> {
    use disrobe_core::recovery::ConfidenceTier;
    if report.passes.is_empty() {
        return None;
    }
    let sum: f64 = report
        .passes
        .iter()
        .map(|p: &disrobe_core::chain::ChainPassRecovery| f64::from(p.confidence.rank()))
        .sum();
    let max_per_pass: f64 = f64::from(ConfidenceTier::Exact.rank());
    let count: f64 = report.passes.len() as f64;
    Some((sum / count / max_per_pass).clamp(0.0, 1.0))
}

fn chain_pass_names(report: &disrobe_core::chain::ChainRecoveryReport) -> Vec<String> {
    report
        .passes
        .iter()
        .map(|p: &disrobe_core::chain::ChainPassRecovery| p.name.clone())
        .collect()
}

fn anti_analysis_lines(anti: &disrobe_core::anti_analysis::AntiAnalysisReport) -> Vec<String> {
    anti.findings
        .iter()
        .map(disrobe_core::anti_analysis::AntiAnalysisFinding::one_line)
        .collect()
}

fn detected_format(doc: &disrobe_core::chain::ChainDocument) -> Option<String> {
    doc.final_format
        .clone()
        .or_else(|| doc.input.detected.first().cloned())
}

fn in_scope(relative: &Path, include: &GlobMatcher, exclude: &GlobMatcher) -> bool {
    let rel: String = relative.to_string_lossy().replace('\\', "/");
    if exclude.matches_any(&rel) {
        return false;
    }
    if include.is_empty() {
        return true;
    }
    include.matches_any(&rel)
}

fn collect_files(root: &Path, opts: &BatchOptions) -> miette::Result<Vec<(PathBuf, PathBuf)>> {
    let include: GlobMatcher = GlobMatcher::compile(&opts.include);
    let exclude: GlobMatcher = GlobMatcher::compile(&opts.exclude);
    let mut walker: WalkDir = WalkDir::new(root).follow_links(false);
    if let Some(depth) = opts.max_depth {
        walker = walker.max_depth(depth.saturating_add(1));
    }
    let mut files: Vec<(PathBuf, PathBuf)> = Vec::new();
    for entry in walker
        .into_iter()
        .filter_entry(|e: &DirEntry| e.depth() == 0 || !is_hidden(e) || e.file_type().is_file())
    {
        let entry: DirEntry = match entry {
            Ok(e) => e,
            Err(_e) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path: PathBuf = entry.into_path();
        let relative: PathBuf = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        if in_scope(&relative, &include, &exclude) {
            files.push((path, relative));
        }
    }
    files.sort_by(|a: &(PathBuf, PathBuf), b: &(PathBuf, PathBuf)| a.1.cmp(&b.1));
    Ok(files)
}

fn process_one(path: &Path, relative: &Path, opts: &BatchOptions) -> ManifestEntry {
    let started: Instant = Instant::now();
    let size: u64 = std::fs::metadata(path).map_or(0, |m: std::fs::Metadata| m.len());
    let rel_display: String = relative.to_string_lossy().replace('\\', "/");
    let stem: String = relative_stem(relative);
    let out_dir: PathBuf = opts.out_root.join(&stem);
    let bytes: Vec<u8> = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return ManifestEntry {
                input: path.display().to_string(),
                relative: rel_display,
                size,
                detected_format: None,
                chain: Vec::new(),
                verdict: None,
                recovery_score: None,
                anti_analysis: Vec::new(),
                output_dir: None,
                duration_ms: started.elapsed().as_millis(),
                error: Some(format!("read failed: {e}")),
            };
        }
    };
    match chain_v1::run_chain_to_dir(
        &path.display().to_string(),
        bytes,
        &out_dir,
        &opts.chain_arg,
        opts.capture_stages,
    ) {
        Ok(ChainOutcome { doc, report, anti }) => ManifestEntry {
            input: path.display().to_string(),
            relative: rel_display,
            size,
            detected_format: detected_format(&doc),
            chain: chain_pass_names(&report),
            verdict: Some(format!("{:?}", doc.verdict)),
            recovery_score: recovery_score(&report),
            anti_analysis: anti_analysis_lines(&anti),
            output_dir: Some(out_dir.display().to_string()),
            duration_ms: started.elapsed().as_millis(),
            error: None,
        },
        Err(e) => ManifestEntry {
            input: path.display().to_string(),
            relative: rel_display,
            size,
            detected_format: None,
            chain: Vec::new(),
            verdict: None,
            recovery_score: None,
            anti_analysis: Vec::new(),
            output_dir: None,
            duration_ms: started.elapsed().as_millis(),
            error: Some(format!("{e}")),
        },
    }
}

const fn classify(entry: &ManifestEntry, summary: &mut BatchSummary) {
    summary.processed += 1;
    if entry.error.is_some() {
        summary.errors += 1;
    } else if entry.chain.is_empty() {
        summary.detect_only += 1;
    } else {
        summary.recovered += 1;
    }
}

pub(crate) fn compute_manifest(root: &Path, opts: &BatchOptions) -> miette::Result<BatchManifest> {
    let files: Vec<(PathBuf, PathBuf)> = collect_files(root, opts)?;
    let bar: ActiveProgress = progress_ui::make_progress("disrobe auto");
    bar.set_total(u64::try_from(files.len()).unwrap_or(u64::MAX));
    let entries: Vec<ManifestEntry> = if opts.jobs <= 1 || files.len() <= 1 {
        files
            .iter()
            .map(|(path, relative): &(PathBuf, PathBuf)| {
                let label: String = relative.to_string_lossy().replace('\\', "/");
                bar.set_message(&label);
                let entry: ManifestEntry = process_one(path, relative, opts);
                bar.tick();
                entry
            })
            .collect()
    } else {
        run_parallel(&files, opts, &bar)?
    };
    bar.finish(&format!("{} file(s) processed", entries.len()));
    let mut summary: BatchSummary = BatchSummary::default();
    for entry in &entries {
        classify(entry, &mut summary);
    }
    std::fs::create_dir_all(&opts.out_root)
        .map_err(|e| miette::miette!("DR-CLI-0340: cannot create batch out dir: {e}"))?;
    let manifest: BatchManifest = BatchManifest {
        schema: MANIFEST_SCHEMA_VERSION.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        root: root.display().to_string(),
        out_root: opts.out_root.display().to_string(),
        chain: opts.chain_arg.clone(),
        jobs: opts.jobs,
        summary,
        entries,
    };
    let manifest_path: PathBuf = opts.out_root.join("manifest.json");
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0341: manifest.json serialize: {e}"))?;
    std::fs::write(&manifest_path, &manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0342: cannot write manifest.json: {e}"))?;
    Ok(manifest)
}

pub(crate) fn run_dir(root: PathBuf, opts: BatchOptions, fmt: OutputFormat) -> miette::Result<()> {
    let manifest: BatchManifest = compute_manifest(&root, &opts)?;
    let manifest_path_str: String = opts.out_root.join("manifest.json").display().to_string();
    emit(fmt, &manifest, || {
        println!("disrobe auto (batch)");
        println!("  root:        {}", manifest.root);
        println!("  out:         {}", manifest.out_root);
        println!("  chain:       {}", manifest.chain);
        println!("  jobs:        {}", manifest.jobs);
        println!(
            "  files:       {} processed, {} recovered, {} detect-only, {} errors",
            manifest.summary.processed,
            manifest.summary.recovered,
            manifest.summary.detect_only,
            manifest.summary.errors
        );
        for entry in &manifest.entries {
            let status: &str = if entry.error.is_some() {
                "ERR "
            } else if entry.chain.is_empty() {
                "scan"
            } else {
                "ok  "
            };
            let score: String = entry
                .recovery_score
                .map_or_else(|| "-".to_string(), |s: f64| format!("{s:.2}"));
            println!(
                "    [{status}] {:<48} score={score:<5} {}",
                entry.relative,
                entry.error.as_deref().unwrap_or("")
            );
        }
        println!("  manifest:    {manifest_path_str}");
    })
}

fn run_parallel(
    files: &[(PathBuf, PathBuf)],
    opts: &BatchOptions,
    bar: &ActiveProgress,
) -> miette::Result<Vec<ManifestEntry>> {
    let pool: rayon::ThreadPool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.jobs)
        .build()
        .map_err(|e| miette::miette!("DR-CLI-0343: cannot build batch thread pool: {e}"))?;
    let slots: Vec<Mutex<Option<ManifestEntry>>> =
        (0..files.len()).map(|_| Mutex::new(None)).collect();
    pool.scope(|scope: &rayon::Scope<'_>| {
        for (idx, (path, relative)) in files.iter().enumerate() {
            let slot: &Mutex<Option<ManifestEntry>> = &slots[idx];
            scope.spawn(move |_| {
                let entry: ManifestEntry = process_one(path, relative, opts);
                bar.tick();
                if let Ok(mut guard) = slot.lock() {
                    *guard = Some(entry);
                }
            });
        }
    });
    let mut out: Vec<ManifestEntry> = Vec::with_capacity(files.len());
    for slot in slots {
        let entry: ManifestEntry = slot
            .into_inner()
            .map_err(|_e| miette::miette!("DR-CLI-0344: batch worker slot poisoned"))?
            .ok_or_else(|| miette::miette!("DR-CLI-0345: batch worker produced no result"))?;
        out.push(entry);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp_dir(stem: &str) -> PathBuf {
        let pid: u32 = std::process::id();
        let n: u64 = SEQ.fetch_add(1, Ordering::Relaxed);
        let p: PathBuf = std::env::temp_dir().join(format!("disrobe-batch-{stem}-{pid}-{n}"));
        std::fs::create_dir_all(&p).expect("mk tmp dir");
        p
    }

    fn opts_for(_root: &Path, out: &Path) -> BatchOptions {
        BatchOptions {
            out_root: out.to_path_buf(),
            chain_arg: "auto:8".to_string(),
            max_depth: None,
            include: Vec::new(),
            exclude: Vec::new(),
            jobs: 1,
            capture_stages: false,
        }
    }

    #[test]
    fn relative_stem_is_filesystem_safe() {
        assert_eq!(relative_stem(Path::new("a/b/c.bin")), "a-b-c.bin");
        assert_eq!(relative_stem(Path::new("x.py")), "x.py");
        assert_eq!(relative_stem(Path::new("")), "file");
    }

    #[test]
    fn collect_respects_exclude_glob() {
        let root: PathBuf = tmp_dir("collect-excl");
        std::fs::write(root.join("keep.txt"), b"a").expect("w");
        std::fs::write(root.join("drop.log"), b"b").expect("w");
        let mut opts: BatchOptions = opts_for(&root, &root.join("out"));
        opts.exclude = vec!["*.log".to_string()];
        let files: Vec<(PathBuf, PathBuf)> = collect_files(&root, &opts).expect("collect");
        assert_eq!(files.len(), 1, "the .log file must be excluded");
        assert!(files[0].0.ends_with("keep.txt"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn collect_respects_include_glob_and_depth() {
        let root: PathBuf = tmp_dir("collect-incl");
        std::fs::create_dir_all(root.join("sub/deeper")).expect("mk");
        std::fs::write(root.join("top.bin"), b"a").expect("w");
        std::fs::write(root.join("sub/mid.bin"), b"b").expect("w");
        std::fs::write(root.join("sub/mid.txt"), b"c").expect("w");
        std::fs::write(root.join("sub/deeper/low.bin"), b"d").expect("w");
        let mut opts: BatchOptions = opts_for(&root, &root.join("out"));
        opts.include = vec!["**/*.bin".to_string(), "*.bin".to_string()];
        opts.max_depth = Some(1);
        let files: Vec<(PathBuf, PathBuf)> = collect_files(&root, &opts).expect("collect");
        let names: Vec<String> = files
            .iter()
            .map(|(_p, r): &(PathBuf, PathBuf)| r.to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(names.contains(&"top.bin".to_string()), "got {names:?}");
        assert!(names.contains(&"sub/mid.bin".to_string()), "got {names:?}");
        assert!(
            !names.iter().any(|n: &String| n.contains("deeper")),
            "max_depth=1 must exclude the depth-2 file; got {names:?}"
        );
        assert!(
            !names.contains(&"sub/mid.txt".to_string()),
            "include=*.bin must drop the .txt; got {names:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn batch_writes_manifest_with_per_file_entries() {
        let root: PathBuf = tmp_dir("manifest");
        std::fs::write(root.join("a.txt"), b"plain text one").expect("w");
        std::fs::write(root.join("b.bin"), vec![0u8; 32]).expect("w");
        let out: PathBuf = tmp_dir("manifest-out");
        let opts: BatchOptions = opts_for(&root, &out);
        run_dir(root.clone(), opts, OutputFormat::Text).expect("batch run");
        let manifest_path: PathBuf = out.join("manifest.json");
        assert!(manifest_path.is_file(), "manifest.json must be written");
        let text: String = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest: BatchManifest = serde_json::from_str(&text).expect("parse manifest");
        assert_eq!(manifest.schema, MANIFEST_SCHEMA_VERSION);
        assert_eq!(manifest.summary.processed, 2);
        assert_eq!(
            manifest.summary.recovered + manifest.summary.detect_only + manifest.summary.errors,
            2,
            "every file must be classified exactly once"
        );
        assert_eq!(manifest.entries.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn one_unreadable_file_does_not_abort_batch() {
        let root: PathBuf = tmp_dir("resilient");
        std::fs::write(root.join("ok.txt"), b"fine").expect("w");
        let dir_as_file: PathBuf = root.join("trap");
        std::fs::create_dir_all(&dir_as_file).expect("mk dir");
        std::fs::write(dir_as_file.join("nested.txt"), b"nested").expect("w");
        let out: PathBuf = tmp_dir("resilient-out");
        let opts: BatchOptions = opts_for(&root, &out);
        run_dir(root.clone(), opts, OutputFormat::Text).expect("batch must not error out");
        let manifest: BatchManifest = serde_json::from_str(
            &std::fs::read_to_string(out.join("manifest.json")).expect("read"),
        )
        .expect("parse");
        assert_eq!(manifest.summary.processed, 2, "two files seen");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn parallel_and_serial_agree_on_entry_count() {
        let root: PathBuf = tmp_dir("par");
        for i in 0..6 {
            std::fs::write(root.join(format!("f{i}.txt")), format!("content {i}")).expect("w");
        }
        let out_serial: PathBuf = tmp_dir("par-serial");
        let out_par: PathBuf = tmp_dir("par-par");
        let mut serial: BatchOptions = opts_for(&root, &out_serial);
        serial.jobs = 1;
        run_dir(root.clone(), serial, OutputFormat::Text).expect("serial");
        let mut par: BatchOptions = opts_for(&root, &out_par);
        par.jobs = 4;
        run_dir(root.clone(), par, OutputFormat::Text).expect("parallel");
        let m_serial: BatchManifest = serde_json::from_str(
            &std::fs::read_to_string(out_serial.join("manifest.json")).unwrap(),
        )
        .unwrap();
        let m_par: BatchManifest =
            serde_json::from_str(&std::fs::read_to_string(out_par.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(m_serial.entries.len(), 6);
        assert_eq!(m_par.entries.len(), 6);
        assert_eq!(m_serial.summary.processed, m_par.summary.processed);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&out_serial);
        let _ = std::fs::remove_dir_all(&out_par);
    }
}
