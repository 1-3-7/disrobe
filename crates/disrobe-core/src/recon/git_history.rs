use std::collections::BTreeSet;
use std::ops::ControlFlow;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{ReconConfig, ReconError, ReconFinding, scan_blob};

const MAX_HISTORY_COMMITS: usize = 100_000;
const MAX_HISTORY_BLOB_BYTES: usize = 16 << 20;
const MAX_HISTORY_BLOBS: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct GitHistoryOptions {
    pub recon: ReconConfig,
    pub max_commits: usize,
}

impl Default for GitHistoryOptions {
    fn default() -> Self {
        Self {
            recon: ReconConfig::default(),
            max_commits: MAX_HISTORY_COMMITS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitFinding {
    pub commit: String,
    pub author_name: String,
    pub author_email: String,
    pub commit_time_unix: i64,
    pub blob_path: String,
    #[serde(flatten)]
    pub finding: ReconFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHistoryReport {
    pub schema: &'static str,
    pub repo: String,
    pub commits_scanned: usize,
    pub blobs_scanned: usize,
    pub bytes_scanned: u64,
    pub total: usize,
    pub findings: Vec<GitFinding>,
}

pub const GIT_HISTORY_SCHEMA: &str = "disrobe.recon.git/v0";

#[derive(Clone)]
struct CommitMeta {
    sha: String,
    author_name: String,
    author_email: String,
    time_unix: i64,
}

/// Scans every reachable commit's added or changed blobs for the same secret,
/// endpoint, and IOC signals as the working-tree scanner, attributing each
/// finding to the commit SHA, author, and in-repo path.
///
/// A working-tree walk only sees the current checkout; this walks history, so a
/// secret that was committed and later deleted is still surfaced. Each blob is
/// read once per `(commit, oid)` pair under a per-blob and total-count budget so
/// a pathological repository cannot exhaust memory.
pub fn report_git(
    repo_path: &Path,
    opts: &GitHistoryOptions,
) -> Result<GitHistoryReport, ReconError> {
    let repo: gix::Repository = gix::discover(repo_path).map_err(|e| ReconError::Io {
        path: repo_path.display().to_string(),
        source: e.to_string(),
    })?;

    let mut tips: Vec<gix::ObjectId> = Vec::new();
    let head: gix::Id<'_> = repo.head_id().map_err(|e| git_error(repo_path, e))?;
    tips.push(head.detach());
    for reference in repo
        .references()
        .map_err(|e| git_error(repo_path, e))?
        .all()
        .map_err(|e| git_error(repo_path, e))?
    {
        let mut reference: gix::Reference<'_> = reference.map_err(|e| git_error(repo_path, e))?;
        let id: gix::Id<'_> = reference
            .peel_to_id()
            .map_err(|e| git_error(repo_path, e))?;
        tips.push(id.detach());
    }
    if tips.is_empty() {
        return Err(ReconError::Io {
            path: repo_path.display().to_string(),
            source: "no reachable references in repository".to_owned(),
        });
    }

    let walk: gix::revision::Walk<'_> = repo
        .rev_walk(tips)
        .sorting(gix::revision::walk::Sorting::BreadthFirst)
        .all()
        .map_err(|e| ReconError::Io {
            path: repo_path.display().to_string(),
            source: e.to_string(),
        })?;

    let mut findings: Vec<GitFinding> = Vec::new();
    let mut seen_blobs: BTreeSet<(gix::ObjectId, String)> = BTreeSet::new();
    let mut commits_scanned: usize = 0;
    let mut blobs_scanned: usize = 0;
    let mut bytes_scanned: u64 = 0;

    for info in walk {
        if commits_scanned >= opts.max_commits || blobs_scanned >= MAX_HISTORY_BLOBS {
            break;
        }
        let info: gix::revision::walk::Info<'_> = info.map_err(|e| git_error(repo_path, e))?;
        let commit: gix::Commit<'_> = info.object().map_err(|e| git_error(repo_path, e))?;
        commits_scanned += 1;

        let meta: CommitMeta = commit_meta(&commit);
        let new_tree: gix::Tree<'_> = commit.tree().map_err(|e| git_error(repo_path, e))?;

        let parents: Vec<gix::ObjectId> = commit
            .parent_ids()
            .map(|p: gix::Id<'_>| p.detach())
            .collect();
        let changed: Vec<(gix::ObjectId, String)> = if parents.is_empty() {
            collect_tree_blobs(&new_tree, repo_path)?
        } else {
            let mut acc: Vec<(gix::ObjectId, String)> = Vec::new();
            for parent in &parents {
                let parent_commit: gix::Commit<'_> = repo
                    .find_commit(*parent)
                    .map_err(|e| git_error(repo_path, e))?;
                let old_tree: gix::Tree<'_> =
                    parent_commit.tree().map_err(|e| git_error(repo_path, e))?;
                acc.extend(diff_added_blobs(&old_tree, &new_tree, repo_path)?);
            }
            acc
        };

        for (oid, blob_path) in changed {
            if blobs_scanned >= MAX_HISTORY_BLOBS {
                break;
            }
            if !seen_blobs.insert((oid, blob_path.clone())) {
                continue;
            }
            let object: gix::Object<'_> =
                repo.find_object(oid).map_err(|e| git_error(repo_path, e))?;
            if object.kind != gix::object::Kind::Blob {
                continue;
            }
            let data: &[u8] = &object.data;
            if data.len() > MAX_HISTORY_BLOB_BYTES {
                continue;
            }
            blobs_scanned += 1;
            bytes_scanned += data.len() as u64;
            let (blob_findings, _): (Vec<ReconFinding>, bool) =
                scan_blob(data, Some(&blob_path), &opts.recon);
            for finding in blob_findings {
                findings.push(GitFinding {
                    commit: meta.sha.clone(),
                    author_name: meta.author_name.clone(),
                    author_email: meta.author_email.clone(),
                    commit_time_unix: meta.time_unix,
                    blob_path: blob_path.clone(),
                    finding,
                });
            }
        }
    }

    findings.sort_by(|a: &GitFinding, b: &GitFinding| {
        a.commit
            .cmp(&b.commit)
            .then_with(|| a.blob_path.cmp(&b.blob_path))
            .then_with(|| a.finding.rule_id.cmp(&b.finding.rule_id))
            .then_with(|| a.finding.value.cmp(&b.finding.value))
    });
    findings.dedup_by(|a: &mut GitFinding, b: &mut GitFinding| {
        a.commit == b.commit
            && a.blob_path == b.blob_path
            && a.finding.rule_id == b.finding.rule_id
            && a.finding.value == b.finding.value
    });

    Ok(GitHistoryReport {
        schema: GIT_HISTORY_SCHEMA,
        repo: repo_path.display().to_string().replace('\\', "/"),
        commits_scanned,
        blobs_scanned,
        bytes_scanned,
        total: findings.len(),
        findings,
    })
}

fn git_error(repo_path: &Path, source: impl std::fmt::Display) -> ReconError {
    ReconError::Io {
        path: repo_path.display().to_string(),
        source: source.to_string(),
    }
}

fn commit_meta(commit: &gix::Commit<'_>) -> CommitMeta {
    let sha: String = commit.id().to_hex().to_string();
    let (author_name, author_email): (String, String) = commit.author().map_or_else(
        |_| (String::new(), String::new()),
        |sig: gix::actor::SignatureRef<'_>| (sig.name.to_string(), sig.email.to_string()),
    );
    let time_unix: i64 = commit.time().map_or(0, |t: gix::date::Time| t.seconds);
    CommitMeta {
        sha,
        author_name,
        author_email,
        time_unix,
    }
}

fn diff_added_blobs(
    old_tree: &gix::Tree<'_>,
    new_tree: &gix::Tree<'_>,
    repo_path: &Path,
) -> Result<Vec<(gix::ObjectId, String)>, ReconError> {
    let mut out: Vec<(gix::ObjectId, String)> = Vec::new();
    let mut platform: gix::object::tree::diff::Platform<'_, '_> =
        old_tree.changes().map_err(|e| git_error(repo_path, e))?;
    platform.options(|opts: &mut gix::diff::Options| {
        opts.track_path();
    });
    platform
        .for_each_to_obtain_tree(
            new_tree,
            |change: gix::object::tree::diff::Change<'_, '_, '_>| {
                use gix::object::tree::diff::Change;
                match change {
                    Change::Addition { location, id, .. }
                    | Change::Modification { location, id, .. }
                    | Change::Rewrite { location, id, .. } => {
                        out.push((id.detach(), location.to_string()));
                    }
                    Change::Deletion { .. } => {}
                }
                Ok::<ControlFlow<()>, std::convert::Infallible>(ControlFlow::Continue(()))
            },
        )
        .map_err(|e| git_error(repo_path, e))?;
    Ok(out)
}

fn collect_tree_blobs(
    tree: &gix::Tree<'_>,
    repo_path: &Path,
) -> Result<Vec<(gix::ObjectId, String)>, ReconError> {
    let entries: Vec<gix::traverse::tree::recorder::Entry> =
        tree.traverse()
            .breadthfirst
            .files()
            .map_err(|e| git_error(repo_path, e))?;
    Ok(entries
        .into_iter()
        .filter(|entry: &gix::traverse::tree::recorder::Entry| entry.mode.is_blob())
        .map(|entry: gix::traverse::tree::recorder::Entry| (entry.oid, entry.filepath.to_string()))
        .collect())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::process::Command;

    use super::*;

    fn aws_akid() -> String {
        format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB")
    }

    fn git(dir: &Path, args: &[&str]) {
        let status: std::process::ExitStatus = Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Frisk Tester")
            .env("GIT_AUTHOR_EMAIL", "frisk@example.test")
            .env("GIT_COMMITTER_NAME", "Frisk Tester")
            .env("GIT_COMMITTER_EMAIL", "frisk@example.test")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .map(|o: std::process::Output| o.status)
            .expect("git must be on PATH for the git-history oracle");
        assert!(status.success(), "git {args:?} failed");
    }

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
    }

    fn temp_repo() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut base: std::path::PathBuf = std::env::temp_dir();
        let unique: String = format!(
            "disrobe-githist-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        base.push(unique);
        std::fs::create_dir_all(&base).expect("create temp repo dir");
        git(&base, &["init", "-q", "-b", "main"]);
        base
    }

    #[test]
    fn finds_secret_deleted_in_a_later_commit() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let repo: std::path::PathBuf = temp_repo();
        let secret_file: std::path::PathBuf = repo.join("config.env");
        let key: String = aws_akid();
        std::fs::write(&secret_file, format!("AWS_ACCESS_KEY_ID={key}\n")).unwrap();
        git(&repo, &["add", "config.env"]);
        git(&repo, &["commit", "-q", "-m", "add config"]);

        std::fs::remove_file(&secret_file).unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "remove config"]);

        assert!(
            !repo.join("config.env").exists(),
            "working tree must no longer contain the secret"
        );

        let report: GitHistoryReport =
            report_git(&repo, &GitHistoryOptions::default()).expect("git history scan");
        let hit: Option<&GitFinding> = report
            .findings
            .iter()
            .find(|gf: &&GitFinding| gf.finding.rule_id == "DR-SEC-AWS-AKID");
        let hit: &GitFinding = hit.unwrap_or_else(|| {
            panic!(
                "history scan must surface the deleted AWS key: {:?}",
                report.findings
            )
        });
        assert_eq!(hit.blob_path, "config.env");
        assert_eq!(hit.author_email, "frisk@example.test");
        assert!(!hit.commit.is_empty());
        assert!(report.commits_scanned >= 2, "{}", report.commits_scanned);

        let working_tree: super::super::ReconReport =
            super::super::report_tree(&repo, &ReconConfig::default()).expect("tree scan");
        assert!(
            working_tree
                .findings
                .iter()
                .all(|f: &ReconFinding| f.rule_id != "DR-SEC-AWS-AKID"
                    || !f.value.starts_with("AKIA")),
            "a working-tree walk must miss the deleted secret, proving the oracle is non-circular"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn report_serializes_with_commit_attribution() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let repo: std::path::PathBuf = temp_repo();
        let key: String = aws_akid();
        std::fs::write(repo.join("a.txt"), format!("k={key}\n")).unwrap();
        git(&repo, &["add", "a.txt"]);
        git(&repo, &["commit", "-q", "-m", "seed"]);

        let report: GitHistoryReport =
            report_git(&repo, &GitHistoryOptions::default()).expect("scan");
        let value: serde_json::Value = serde_json::to_value(&report).expect("serialize");
        assert_eq!(value["schema"], serde_json::json!(GIT_HISTORY_SCHEMA));
        assert!(value["findings"][0]["commit"].is_string());
        assert!(value["findings"][0]["blob_path"].is_string());
        assert!(value["findings"][0]["rule_id"].is_string());

        let _ = std::fs::remove_dir_all(&repo);
    }
}
