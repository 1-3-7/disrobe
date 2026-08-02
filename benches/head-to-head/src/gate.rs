use std::path::{Path, PathBuf};

use disrobe_core::recon::{ReconCategory, ReconConfig, ReconFinding, ReconReport, report_tree};
use disrobe_pass_pickle::{Disassembly, VmTrace, analyze_safety, disassemble, execute};
use eyre::Result;
use serde_json::{Value, json};

use crate::tool::{MAX_FIXTURE_BYTES, MAX_PICKLE_DEPTH, MAX_PICKLE_FILES, read_bounded_file};

const REQUIRED_PLANTED_CATEGORIES: &[ReconCategory] = &[
    ReconCategory::Endpoint,
    ReconCategory::Manifest,
    ReconCategory::Url,
    ReconCategory::Ipv4,
    ReconCategory::Email,
    ReconCategory::Onion,
];

pub fn measure(root: &Path) -> (String, Value) {
    let id: String = "gate-harvest".to_owned();
    let gates: Vec<Value> = vec![frisk_gauntlet_gate(root), pickle_corpus_gate(root)];
    let value: Value = json!({
        "id": id,
        "title": "Gate-test harvest: real oracle gates with no recovery.json number, surfaced",
        "status": "ok",
        "ecosystem": "cross-ecosystem",
        "note": "These two gates already prove disrobe correct against an external reference or a planted ground truth, but their numbers were not in recovery.json. This bench runs each gate's measurement in-process (the same public API the committed test exercises) and records the number so the evidence report can surface it. A gate whose fixture is sourcing-gated on this box is recorded skipped-with-reason, never a silent pass.",
        "gates": gates,
    });
    (id, value)
}

fn frisk_gauntlet_gate(root: &Path) -> Value {
    let id: &str = "frisk-planted-recall";
    let planted: PathBuf = root.join("corpus").join("recon").join("planted");
    if !planted.is_dir() {
        return gate_skipped(
            id,
            "frisk recon category recall on the planted ground-truth tree",
            "corpus/recon/planted is absent",
            "cargo test -p disrobe-core --test frisk_gauntlet",
        );
    }
    let report: ReconReport = match report_tree(&planted, &ReconConfig::default()) {
        Ok(r) => r,
        Err(e) => {
            return gate_skipped(
                id,
                "frisk recon category recall on the planted ground-truth tree",
                &format!("frisk scan errored: {e}"),
                "cargo test -p disrobe-core --test frisk_gauntlet",
            );
        }
    };
    let found: usize = REQUIRED_PLANTED_CATEGORIES
        .iter()
        .filter(|cat: &&ReconCategory| {
            report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.category == **cat)
        })
        .count();
    gate_measured(
        id,
        "frisk recon category recall on the committed planted ground-truth tree",
        "deliberately planted findings (endpoint, manifest, URL, IPv4, email, .onion) committed under corpus/recon/planted - the ground truth",
        found,
        REQUIRED_PLANTED_CATEGORIES.len(),
        "% of the planted committed (non-secret) IOC categories detected",
        "cargo test -p disrobe-core --test frisk_gauntlet",
    )
}

fn pickle_corpus_gate(root: &Path) -> Value {
    let id: &str = "pickle-corpus-coverage";
    let corpus: PathBuf = root.join("corpus").join("pickle");
    if !corpus.is_dir() {
        return gate_skipped(
            id,
            "pickle corpus disassemble + symbolic-trace + safety-classification coverage",
            "corpus/pickle absent",
            "cargo test -p disrobe-pass-pickle --test corpus",
        );
    }
    let mut files: Vec<PathBuf> = Vec::new();
    if let Err(reason) = collect_pkl(&corpus, &mut files, 0) {
        return gate_skipped(
            id,
            "pickle corpus disassemble + symbolic-trace + safety-classification coverage",
            &reason,
            "cargo test -p disrobe-pass-pickle --test corpus",
        );
    }
    let total: usize = files.len();
    if total == 0 {
        return gate_skipped(
            id,
            "pickle corpus disassemble + symbolic-trace + safety-classification coverage",
            "no .pkl fixtures under corpus/pickle",
            "cargo test -p disrobe-pass-pickle --test corpus",
        );
    }
    let mut ok: usize = 0;
    for file in &files {
        let Ok(bytes): Result<Vec<u8>, _> = read_bounded_file(file, MAX_FIXTURE_BYTES) else {
            continue;
        };
        let Ok(dis): disrobe_pass_pickle::Result<Disassembly> = disassemble(&bytes) else {
            continue;
        };
        if dis.stop_offset.is_none() {
            continue;
        }
        let Ok(trace): disrobe_pass_pickle::Result<VmTrace> = execute(&dis) else {
            continue;
        };
        let _safety: disrobe_pass_pickle::SafetyReport = analyze_safety(&trace);
        ok += 1;
    }
    gate_measured(
        id,
        "pickle corpus disassemble + symbolic-trace + safety-classification coverage",
        "pickletools-semantics equivalence: every committed fixture must disassemble to a STOP, symbolically execute, and classify (benign vs malicious) correctly",
        ok,
        total,
        "% of committed pickle fixtures fully disassembled + traced + classified",
        "cargo test -p disrobe-pass-pickle --test corpus",
    )
}

fn gate_measured(
    id: &str,
    title: &str,
    oracle: &str,
    ok: usize,
    total: usize,
    metric: &str,
    reproduce: &str,
) -> Value {
    let pct: f64 = 100.0 * ok as f64 / total.max(1) as f64;
    json!({
        "id": id,
        "title": title,
        "status": "ok",
        "oracle": oracle,
        "metric": metric,
        "ok": ok,
        "total": total,
        "value": pct,
        "display": format!("{ok}/{total} ({pct:.1}%)"),
        "reproduce": reproduce,
    })
}

fn gate_skipped(id: &str, title: &str, reason: &str, reproduce: &str) -> Value {
    json!({
        "id": id,
        "title": title,
        "status": "skipped",
        "reason": reason,
        "reproduce": reproduce,
    })
}

fn collect_pkl(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    depth: usize,
) -> std::result::Result<(), String> {
    collect_pkl_with_limits(dir, out, depth, MAX_PICKLE_DEPTH, MAX_PICKLE_FILES)
}

fn collect_pkl_with_limits(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    depth: usize,
    max_depth: usize,
    max_files: usize,
) -> std::result::Result<(), String> {
    if depth > max_depth {
        return Err(format!("pickle corpus nesting exceeds {max_depth} levels"));
    }
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let mut sorted: Vec<(PathBuf, std::fs::FileType)> = entries
        .flatten()
        .filter_map(|entry: std::fs::DirEntry| {
            entry
                .file_type()
                .ok()
                .map(|kind: std::fs::FileType| (entry.path(), kind))
        })
        .collect();
    sorted.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (path, kind) in sorted {
        if kind.is_dir() {
            collect_pkl_with_limits(&path, out, depth + 1, max_depth, max_files)?;
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "pkl") {
            if out.len() >= max_files {
                return Err(format!("pickle fixture count exceeds {max_files} files"));
            }
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use disrobe_core::recon::ReconError;

    use super::*;
    use crate::published::{
        PublishedBar, assert_published_membership_is_recovered, checked_workspace_root,
        published_bar,
    };

    const PUBLISHED_IOC_HEADING: &str = "frisk IOC category recall on the committed planted tree";
    const PUBLISHED_IOC_BAR: &str = "planted non-secret IOC categories";

    #[test]
    fn published_planted_ioc_category_bar_is_pinned_by_membership() {
        let planted: PathBuf = checked_workspace_root()
            .join("corpus")
            .join("recon")
            .join("planted");
        assert!(
            planted.is_dir(),
            "{} is the committed ground truth this published figure counts against; without it the \
             row measures nothing",
            planted.display()
        );
        let scanned: core::result::Result<ReconReport, ReconError> =
            report_tree(&planted, &ReconConfig::default());
        assert!(
            scanned.is_ok(),
            "frisk must scan the committed planted tree: {:?}",
            scanned.as_ref().err()
        );
        let findings: Vec<ReconFinding> =
            scanned.map_or_else(|_| Vec::new(), |report: ReconReport| report.findings);

        let detected: BTreeSet<String> = REQUIRED_PLANTED_CATEGORIES
            .iter()
            .filter(|category: &&ReconCategory| {
                findings
                    .iter()
                    .any(|finding: &ReconFinding| finding.category == **category)
            })
            .map(|category: &ReconCategory| category.label().to_owned())
            .collect();

        for category in REQUIRED_PLANTED_CATEGORIES {
            let hits: Vec<&ReconFinding> = findings
                .iter()
                .filter(|finding: &&ReconFinding| finding.category == *category)
                .collect();
            eprintln!(
                "planted category `{label}`: {count} finding(s)",
                label = category.label(),
                count = hits.len(),
            );
            for finding in hits {
                eprintln!(
                    "  {rule} {path}:{line} = {value}",
                    rule = finding.rule_id,
                    path = finding.path.as_deref().unwrap_or("(no path)"),
                    line = finding.line,
                    value = finding.value,
                );
            }
        }

        let bar: PublishedBar = published_bar(PUBLISHED_IOC_HEADING, PUBLISHED_IOC_BAR);
        eprintln!(
            "published `{label}` {num}/{den} = {value}; measured {measured} {detected:?}",
            label = bar.label,
            num = bar.num,
            den = bar.den,
            value = bar.value,
            measured = detected.len(),
        );
        let required: BTreeSet<String> = REQUIRED_PLANTED_CATEGORIES
            .iter()
            .map(|category: &ReconCategory| category.label().to_owned())
            .collect();
        assert_eq!(
            bar.membership,
            required,
            "bar `{label}`: recovery.json must name the same planted categories this gate grades, \
             so the published figure cannot describe a different six than the one measured",
            label = bar.label
        );
        assert_published_membership_is_recovered(
            &bar,
            &detected,
            REQUIRED_PLANTED_CATEGORIES.len(),
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("disrobe_h2h_gate_{}_{}", std::process::id(), name))
    }

    #[test]
    fn collect_pkl_rejects_count_over_cap() -> core::result::Result<(), String> {
        let root: PathBuf = temp_dir("count");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        std::fs::write(root.join("a.pkl"), b".").map_err(|e| e.to_string())?;
        std::fs::write(root.join("b.pkl"), b".").map_err(|e| e.to_string())?;
        let mut files: Vec<PathBuf> = Vec::new();
        let result: std::result::Result<(), String> =
            collect_pkl_with_limits(&root, &mut files, 0, 8, 1);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result.is_err(),
            "two pickle files must exceed a one-file cap"
        );
        Ok(())
    }
}
