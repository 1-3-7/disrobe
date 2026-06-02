#![cfg(feature = "chain")]

use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::output::{OutputFormat, emit};

const STAGE_LOCK_FILENAME: &str = ".disrobe-stage-lock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuardReason {
    StageMirrorContainment,
    StageLockSentinel,
    ExplicitRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub(crate) enum Decision {
    Allow,
    Deny {
        reason: GuardReason,
        locked_root: String,
    },
}

impl Decision {
    #[inline]
    pub(crate) const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

#[derive(Debug, Clone, Serialize)]
struct GuardCheckReport {
    candidate: String,
    decision: Decision,
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out: PathBuf = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push(Component::ParentDir.as_os_str());
                }
            }
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

fn canonical_with_tail(path: &Path) -> PathBuf {
    let mut existing: PathBuf = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(resolved) = existing.canonicalize() {
            let mut out: PathBuf = resolved;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        let Some(name): Option<&std::ffi::OsStr> = existing.file_name() else {
            return normalize_lexical(path);
        };
        tail.push(name.to_os_string());
        if !existing.pop() {
            return normalize_lexical(path);
        }
    }
}

fn enclosing_out_index(parts: &[Component<'_>]) -> Option<usize> {
    parts.iter().position(|c: &Component<'_>| {
        matches!(c, Component::Normal(name) if name.eq_ignore_ascii_case("out"))
    })
}

fn is_in_stage_mirror(canonical: &Path) -> bool {
    let parts: Vec<Component<'_>> = canonical.components().collect();
    let Some(out_index): Option<usize> = enclosing_out_index(&parts) else {
        return false;
    };
    parts
        .get(out_index + 1..)
        .into_iter()
        .flatten()
        .any(|c: &Component<'_>| match c {
            Component::Normal(name) => {
                **name == *std::ffi::OsStr::new("stages")
                    || **name == *std::ffi::OsStr::new("final")
            }
            _ => false,
        })
}

fn has_stage_lock(canonical: &Path) -> Option<PathBuf> {
    let parts: Vec<Component<'_>> = canonical.components().collect();
    let out_index: Option<usize> = enclosing_out_index(&parts);
    let mut cursor: &Path = if canonical.is_dir() {
        canonical
    } else {
        canonical.parent()?
    };
    loop {
        let candidate: PathBuf = cursor.join(STAGE_LOCK_FILENAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        let at_out_boundary: bool =
            out_index.is_some_and(|idx: usize| cursor.components().count() == idx + 1);
        if at_out_boundary {
            return None;
        }
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => return None,
        }
    }
}

fn inside_any_root(canonical: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    roots
        .iter()
        .find(|root: &&PathBuf| canonical.starts_with(root))
        .cloned()
}

pub(crate) fn guard_decision(candidate: &Path, roots: &[PathBuf]) -> Decision {
    let canonical: PathBuf = canonical_with_tail(candidate);
    if is_in_stage_mirror(&canonical) {
        return Decision::Deny {
            reason: GuardReason::StageMirrorContainment,
            locked_root: canonical.display().to_string(),
        };
    }
    if let Some(lock) = has_stage_lock(&canonical) {
        return Decision::Deny {
            reason: GuardReason::StageLockSentinel,
            locked_root: lock.display().to_string(),
        };
    }
    if let Some(root) = inside_any_root(&canonical, roots) {
        return Decision::Deny {
            reason: GuardReason::ExplicitRoot,
            locked_root: root.display().to_string(),
        };
    }
    Decision::Allow
}

pub(crate) fn run_check(
    candidate: PathBuf,
    roots: Vec<PathBuf>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let canonical_roots: Vec<PathBuf> = roots
        .iter()
        .map(|r: &PathBuf| {
            if r.exists() {
                Ok(canonical_with_tail(r))
            } else {
                Err(miette::miette!(
                    "DR-CLI-0321: guard cannot resolve --root {}",
                    r.display()
                ))
            }
        })
        .collect::<miette::Result<Vec<PathBuf>>>()?;
    let decision: Decision = guard_decision(&candidate, &canonical_roots);
    let report: GuardCheckReport = GuardCheckReport {
        candidate: candidate.display().to_string(),
        decision: decision.clone(),
    };
    emit(fmt, &report, || match &report.decision {
        Decision::Allow => println!(
            "guard allow: {} is not a ground-truth stage path",
            report.candidate
        ),
        Decision::Deny {
            reason,
            locked_root,
        } => println!(
            "guard DENY: {} is protected ({reason:?} via {locked_root})",
            report.candidate
        ),
    })?;
    if decision.is_deny() {
        Err(miette::miette!(
            "DR-CLI-0320: guard denied write to ground-truth stage path {}",
            candidate.display()
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn deny_on_stage_mirror_output_bin() {
        let dir: tempfile::TempDir = tempdir().expect("tempdir");
        let stage_dir: PathBuf = dir
            .path()
            .join("out")
            .join("demo-chain")
            .join("stages")
            .join("00-input");
        std::fs::create_dir_all(&stage_dir).expect("mk stage dir");
        let candidate: PathBuf = stage_dir.join("output.bin");
        std::fs::write(&candidate, b"stage").expect("write stage");
        let decision: Decision = guard_decision(&candidate, &[]);
        assert_eq!(
            decision,
            Decision::Deny {
                reason: GuardReason::StageMirrorContainment,
                locked_root: canonical_with_tail(&candidate).display().to_string(),
            }
        );
    }

    #[test]
    fn deny_on_final_mirror() {
        let dir: tempfile::TempDir = tempdir().expect("tempdir");
        let final_dir: PathBuf = dir.path().join("out").join("x").join("final");
        std::fs::create_dir_all(&final_dir).expect("mk final dir");
        let candidate: PathBuf = final_dir.join("01-pyarmor-unpack");
        std::fs::write(&candidate, b"final").expect("write final");
        let decision: Decision = guard_decision(&candidate, &[]);
        assert!(matches!(
            decision,
            Decision::Deny {
                reason: GuardReason::StageMirrorContainment,
                ..
            }
        ));
    }

    #[test]
    fn deny_on_nonexistent_child_of_stage_dir() {
        let dir: tempfile::TempDir = tempdir().expect("tempdir");
        let stage_dir: PathBuf = dir
            .path()
            .join("out")
            .join("y-chain")
            .join("stages")
            .join("02-deob");
        std::fs::create_dir_all(&stage_dir).expect("mk stage dir");
        let candidate: PathBuf = stage_dir.join("not-yet-written.bin");
        assert!(!candidate.exists());
        let decision: Decision = guard_decision(&candidate, &[]);
        assert!(matches!(
            decision,
            Decision::Deny {
                reason: GuardReason::StageMirrorContainment,
                ..
            }
        ));
    }

    #[test]
    fn deny_on_stage_lock_sentinel() {
        let dir: tempfile::TempDir = tempdir().expect("tempdir");
        let locked_dir: PathBuf = dir.path().join("artifacts").join("frozen");
        std::fs::create_dir_all(&locked_dir).expect("mk locked dir");
        std::fs::write(locked_dir.join(STAGE_LOCK_FILENAME), b"").expect("write lock");
        let candidate: PathBuf = locked_dir.join("payload.txt");
        std::fs::write(&candidate, b"data").expect("write payload");
        let decision: Decision = guard_decision(&candidate, &[]);
        assert!(matches!(
            decision,
            Decision::Deny {
                reason: GuardReason::StageLockSentinel,
                ..
            }
        ));
    }

    #[test]
    fn deny_inside_explicit_root() {
        let dir: tempfile::TempDir = tempdir().expect("tempdir");
        let protected: PathBuf = dir.path().join("protected");
        std::fs::create_dir_all(&protected).expect("mk protected");
        let candidate: PathBuf = protected.join("nested").join("thing.rs");
        let roots: Vec<PathBuf> = vec![canonical_with_tail(&protected)];
        let decision: Decision = guard_decision(&candidate, &roots);
        assert!(matches!(
            decision,
            Decision::Deny {
                reason: GuardReason::ExplicitRoot,
                ..
            }
        ));
    }

    #[test]
    fn allow_on_unrelated_src_file() {
        let dir: tempfile::TempDir = tempdir().expect("tempdir");
        let src_dir: PathBuf = dir.path().join("src");
        std::fs::create_dir_all(&src_dir).expect("mk src");
        let candidate: PathBuf = src_dir.join("foo.rs");
        std::fs::write(&candidate, b"fn main() {}").expect("write src");
        let decision: Decision = guard_decision(&candidate, &[]);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn allow_on_out_sibling_not_stage() {
        let dir: tempfile::TempDir = tempdir().expect("tempdir");
        let out_dir: PathBuf = dir.path().join("out").join("x");
        std::fs::create_dir_all(&out_dir).expect("mk out");
        let candidate: PathBuf = out_dir.join("chain.json");
        std::fs::write(&candidate, b"{}").expect("write chain.json");
        let decision: Decision = guard_decision(&candidate, &[]);
        assert_eq!(decision, Decision::Allow);
    }
}
