use crate::error::{Error, Result};

use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub(crate) use disrobe_bytes::quota::{
    ABSOLUTE_MAX_ENTRIES, BoundedVecWriter, DEFAULT_MAX_ENTRIES, MAX_ENTRY_PREALLOC,
    bounded_prealloc,
};
pub use disrobe_bytes::quota::{ExtractionQuota, QuotaExceeded, QuotaReport};

#[derive(Debug, Clone)]
pub struct QuotaGuard(disrobe_bytes::quota::QuotaGuard);

impl QuotaGuard {
    #[must_use]
    pub const fn new(quota: ExtractionQuota) -> Self {
        Self(disrobe_bytes::quota::QuotaGuard::new(quota))
    }

    pub fn admit_entry(&mut self, name: &str, uncompressed: u64, compressed: u64) -> Result<()> {
        self.0
            .admit_entry(name, uncompressed, compressed)
            .map_err(Error::from)
    }

    #[must_use]
    pub const fn report(&self) -> &QuotaReport {
        self.0.report()
    }

    #[must_use]
    pub const fn max_per_entry_uncompressed(&self) -> u64 {
        self.0.max_per_entry_uncompressed()
    }
}

pub(crate) fn read_entry_to_limit<R: Read + ?Sized>(
    reader: &mut R,
    entry: &str,
    cap: u64,
) -> Result<Vec<u8>> {
    disrobe_bytes::quota::read_to_limit(reader, entry, cap).map_err(
        |error: disrobe_bytes::quota::LimitedReadError| match error {
            disrobe_bytes::quota::LimitedReadError::Io(io) => Error::Io(io),
            disrobe_bytes::quota::LimitedReadError::Quota(exceeded) => Error::from(exceeded),
        },
    )
}

pub(crate) const MAX_ENTRY_PATH_BYTES: usize = 4096;
pub(crate) const MAX_ENTRY_COMPONENT_BYTES: usize = 255;

const RESERVED_DEVICE_STEMS: [&str; 30] = [
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    "conin$", "conout$", "clock$", "config$", "keybd$", "screen$",
];

fn is_reserved_device_component(component: &str) -> bool {
    let stem: &str = component
        .split_once('.')
        .map_or(component, |(head, _tail): (&str, &str)| head);
    let folded: String = stem.trim_end_matches([' ', '\t']).to_ascii_lowercase();
    RESERVED_DEVICE_STEMS.contains(&folded.as_str())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryPathClause {
    OverlongName,
    ControlCharacter,
    RootAnchored,
    OverlongComponent,
    ColonInComponent,
    ParentTraversal,
    TrailingDotOrSpace,
    ReservedDeviceName,
    NothingLeftAfterCleaning,
}

#[cfg(test)]
pub(crate) const ENTRY_PATH_CLAUSES: [EntryPathClause; 9] = [
    EntryPathClause::OverlongName,
    EntryPathClause::ControlCharacter,
    EntryPathClause::RootAnchored,
    EntryPathClause::OverlongComponent,
    EntryPathClause::ColonInComponent,
    EntryPathClause::ParentTraversal,
    EntryPathClause::TrailingDotOrSpace,
    EntryPathClause::ReservedDeviceName,
    EntryPathClause::NothingLeftAfterCleaning,
];

fn note(found: &mut Vec<EntryPathClause>, clause: EntryPathClause) {
    if !found.contains(&clause) {
        found.push(clause);
    }
}

fn component_clauses(component: &str, found: &mut Vec<EntryPathClause>) {
    if component.len() > MAX_ENTRY_COMPONENT_BYTES {
        note(found, EntryPathClause::OverlongComponent);
    }
    if component.contains(':') {
        note(found, EntryPathClause::ColonInComponent);
    }
    if component.chars().all(|c: char| c == '.') {
        note(found, EntryPathClause::ParentTraversal);
    } else if component.ends_with('.') || component.ends_with(' ') {
        note(found, EntryPathClause::TrailingDotOrSpace);
    }
    if is_reserved_device_component(component) {
        note(found, EntryPathClause::ReservedDeviceName);
    }
}

fn inspect_entry_path(name: &str) -> (Vec<EntryPathClause>, String) {
    let mut found: Vec<EntryPathClause> = Vec::new();
    if name.len() > MAX_ENTRY_PATH_BYTES {
        note(&mut found, EntryPathClause::OverlongName);
    }
    if name.chars().any(char::is_control) {
        note(&mut found, EntryPathClause::ControlCharacter);
    }
    let normalized: String = name.replace('\\', "/");
    if normalized.starts_with('/') {
        note(&mut found, EntryPathClause::RootAnchored);
    }
    let mut kept: Vec<&str> = Vec::new();
    for component in normalized.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        component_clauses(component, &mut found);
        kept.push(component);
    }
    if kept.is_empty() {
        note(&mut found, EntryPathClause::NothingLeftAfterCleaning);
    }
    (found, kept.join("/"))
}

#[cfg(test)]
pub(crate) fn entry_path_clauses_violated(name: &str) -> Vec<EntryPathClause> {
    inspect_entry_path(name).0
}

pub fn sanitize_entry_path(name: &str) -> Result<String> {
    let (violations, cleaned): (Vec<EntryPathClause>, String) = inspect_entry_path(name);
    if violations.is_empty() {
        return Ok(cleaned);
    }
    Err(Error::UnsafeEntryPath(name.to_owned()))
}

fn lexically_contained(root: &Path, candidate: &Path) -> bool {
    let Ok(relative): std::result::Result<&Path, std::path::StripPrefixError> =
        candidate.strip_prefix(root)
    else {
        return false;
    };
    relative
        .components()
        .all(|c: Component<'_>| matches!(c, Component::Normal(_) | Component::CurDir))
}

pub(crate) fn resolved_within(root: &Path, candidate: &Path) -> Result<bool> {
    let root_real: PathBuf = std::fs::canonicalize(root)?;
    let candidate_real: PathBuf = std::fs::canonicalize(candidate)?;
    Ok(candidate_real == root_real || candidate_real.starts_with(&root_real))
}

pub fn prepare_entry_dir(out_dir: &Path, dir_name: &str) -> Result<PathBuf> {
    let safe: String = sanitize_entry_path(dir_name)?;
    let joined: PathBuf = out_dir.join(&safe);
    if !lexically_contained(out_dir, &joined) {
        return Err(Error::UnsafeEntryPath(dir_name.to_owned()));
    }
    std::fs::create_dir_all(&joined)?;
    if !resolved_within(out_dir, &joined)? {
        return Err(Error::UnsafeEntryPath(dir_name.to_owned()));
    }
    Ok(joined)
}

pub fn prepare_entry_path(out_dir: &Path, entry_name: &str) -> Result<PathBuf> {
    let safe: String = sanitize_entry_path(entry_name)?;
    let joined: PathBuf = out_dir.join(&safe);
    if !lexically_contained(out_dir, &joined) {
        return Err(Error::UnsafeEntryPath(entry_name.to_owned()));
    }
    if !safe.contains('/') {
        std::fs::create_dir_all(out_dir)?;
        return Ok(joined);
    }
    let Some(parent) = joined.parent() else {
        return Err(Error::UnsafeEntryPath(entry_name.to_owned()));
    };
    std::fs::create_dir_all(parent)?;
    if !resolved_within(out_dir, parent)? {
        return Err(Error::UnsafeEntryPath(entry_name.to_owned()));
    }
    Ok(joined)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostileNameVerdict {
    Refused,
    ContainedWrite,
}

#[cfg(test)]
pub(crate) const HOSTILE_ENTRY_NAMES: &[(&str, HostileNameVerdict)] = &[
    ("../escape.txt", HostileNameVerdict::Refused),
    ("../../../../escape.txt", HostileNameVerdict::Refused),
    ("sub/../../escape.txt", HostileNameVerdict::Refused),
    ("..", HostileNameVerdict::Refused),
    ("../", HostileNameVerdict::Refused),
    ("..\\escape.txt", HostileNameVerdict::Refused),
    ("a\\b/../../escape.txt", HostileNameVerdict::Refused),
    ("/etc/passwd", HostileNameVerdict::Refused),
    ("\\etc\\passwd", HostileNameVerdict::Refused),
    ("C:/Windows/win.ini", HostileNameVerdict::Refused),
    ("C:\\Windows\\win.ini", HostileNameVerdict::Refused),
    ("\\\\?\\C:\\Windows\\win.ini", HostileNameVerdict::Refused),
    ("\\\\server\\share\\escape.txt", HostileNameVerdict::Refused),
    ("//server/share/escape.txt", HostileNameVerdict::Refused),
    ("dir/file.txt:stream", HostileNameVerdict::Refused),
    ("file.txt:$DATA", HostileNameVerdict::Refused),
    ("evil\u{0}.txt", HostileNameVerdict::Refused),
    ("evil\u{1b}.txt", HostileNameVerdict::Refused),
    ("...", HostileNameVerdict::Refused),
    ("dir/....", HostileNameVerdict::Refused),
    ("evil.", HostileNameVerdict::Refused),
    ("dir/evil ", HostileNameVerdict::Refused),
    ("CON", HostileNameVerdict::Refused),
    ("con", HostileNameVerdict::Refused),
    ("con.txt", HostileNameVerdict::Refused),
    ("PRN.log", HostileNameVerdict::Refused),
    ("AUX", HostileNameVerdict::Refused),
    ("NUL.dat", HostileNameVerdict::Refused),
    ("COM1", HostileNameVerdict::Refused),
    ("com9.txt", HostileNameVerdict::Refused),
    ("LPT1", HostileNameVerdict::Refused),
    ("lpt9.dat", HostileNameVerdict::Refused),
    ("dir/CON/file.txt", HostileNameVerdict::Refused),
    ("", HostileNameVerdict::Refused),
    ("///", HostileNameVerdict::Refused),
    ("./", HostileNameVerdict::Refused),
    ("%2e%2e/escape.txt", HostileNameVerdict::ContainedWrite),
    ("..%2fescape.txt", HostileNameVerdict::ContainedWrite),
    (
        "\u{ff0e}\u{ff0e}/escape.txt",
        HostileNameVerdict::ContainedWrite,
    ),
    (
        "\u{2024}\u{2024}/escape.txt",
        HostileNameVerdict::ContainedWrite,
    ),
    ("a\u{2215}b.txt", HostileNameVerdict::ContainedWrite),
    (
        "\u{fffd}\u{fffd}/escape.txt",
        HostileNameVerdict::ContainedWrite,
    ),
    ("./ok.txt", HostileNameVerdict::ContainedWrite),
    ("a//b.txt", HostileNameVerdict::ContainedWrite),
    ("a\\b\\c.txt", HostileNameVerdict::ContainedWrite),
    ("dir/./sub/./ok.txt", HostileNameVerdict::ContainedWrite),
    (".hidden", HostileNameVerdict::ContainedWrite),
    ("..hidden", HostileNameVerdict::ContainedWrite),
    ("CONSOLE.txt", HostileNameVerdict::ContainedWrite),
    ("com10.txt", HostileNameVerdict::ContainedWrite),
];

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hostile_name_table_matches_the_guard_verdict() {
        for (name, verdict) in HOSTILE_ENTRY_NAMES {
            let result: Result<String> = sanitize_entry_path(name);
            match verdict {
                HostileNameVerdict::Refused => assert!(
                    matches!(result, Err(Error::UnsafeEntryPath(_))),
                    "`{name}` must be refused with a typed error, got {result:?}"
                ),
                HostileNameVerdict::ContainedWrite => {
                    let cleaned: String =
                        result.unwrap_or_else(|e: Error| panic!("`{name}` must be kept: {e}"));
                    assert!(
                        !cleaned.starts_with('/')
                            && cleaned.split('/').all(|c: &str| c != ".." && c != "."),
                        "`{name}` cleaned into `{cleaned}`"
                    );
                }
            }
        }
    }

    fn clause_witnesses() -> Vec<(EntryPathClause, String)> {
        vec![
            (
                EntryPathClause::OverlongName,
                format!("{}/x.txt", vec!["dir"; 2048].join("/")),
            ),
            (
                EntryPathClause::ControlCharacter,
                "evil\u{0}.txt".to_owned(),
            ),
            (EntryPathClause::RootAnchored, "/etc/passwd".to_owned()),
            (
                EntryPathClause::OverlongComponent,
                "a".repeat(MAX_ENTRY_COMPONENT_BYTES + 1),
            ),
            (
                EntryPathClause::ColonInComponent,
                "dir/file.txt:stream".to_owned(),
            ),
            (EntryPathClause::ParentTraversal, "../escape.txt".to_owned()),
            (EntryPathClause::TrailingDotOrSpace, "evil.".to_owned()),
            (EntryPathClause::ReservedDeviceName, "CON".to_owned()),
            (EntryPathClause::NothingLeftAfterCleaning, "./".to_owned()),
        ]
    }

    #[test]
    fn every_guard_clause_owns_a_witness_no_other_clause_refuses() {
        let witnesses: Vec<(EntryPathClause, String)> = clause_witnesses();
        for clause in ENTRY_PATH_CLAUSES {
            let matching: Vec<&(EntryPathClause, String)> = witnesses
                .iter()
                .filter(|(c, _): &&(EntryPathClause, String)| *c == clause)
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "{clause:?} needs exactly one witness, found {}",
                matching.len()
            );
        }
        for (clause, witness) in &witnesses {
            let violated: Vec<EntryPathClause> = entry_path_clauses_violated(witness);
            assert_eq!(
                violated,
                vec![*clause],
                "`{witness}` must be refused by {clause:?} alone, got {violated:?}"
            );
            assert!(
                matches!(sanitize_entry_path(witness), Err(Error::UnsafeEntryPath(_))),
                "`{witness}` must be refused while {clause:?} is present"
            );
        }
    }

    #[test]
    fn an_accepted_name_can_never_carry_a_traversal_component() {
        let accepted: Vec<String> = HOSTILE_ENTRY_NAMES
            .iter()
            .filter_map(|(name, _): &(&str, HostileNameVerdict)| sanitize_entry_path(name).ok())
            .chain(
                ["pkg/mod.pyc", "a/b/c.txt", ".hidden"]
                    .into_iter()
                    .filter_map(|name: &str| sanitize_entry_path(name).ok()),
            )
            .collect();
        assert!(accepted.len() >= 12, "too few accepted names to prove this");
        for cleaned in &accepted {
            assert!(
                !cleaned.starts_with('/') && !cleaned.contains('\\'),
                "`{cleaned}` stayed anchored or kept a native separator"
            );
            for component in cleaned.split('/') {
                assert!(
                    !component.is_empty()
                        && !component.chars().all(|c: char| c == '.')
                        && !component.contains(':'),
                    "`{cleaned}` kept the component `{component}`"
                );
            }
        }
    }

    #[test]
    fn hostile_name_table_covers_every_declared_shape() {
        assert!(
            HOSTILE_ENTRY_NAMES.len() >= 50,
            "the hostile-name table must stay exhaustive"
        );
        let refused: usize = HOSTILE_ENTRY_NAMES
            .iter()
            .filter(|(_, v): &&(&str, HostileNameVerdict)| *v == HostileNameVerdict::Refused)
            .count();
        assert!(refused >= 35, "refusal rows dropped to {refused}");
    }

    #[test]
    fn sanitize_rejects_overlong_names() {
        let long_component: String = "a".repeat(MAX_ENTRY_COMPONENT_BYTES + 1);
        assert!(sanitize_entry_path(&long_component).is_err());
        let at_limit: String = "a".repeat(MAX_ENTRY_COMPONENT_BYTES);
        assert!(sanitize_entry_path(&at_limit).is_ok());
        let long_path: String = format!("{}/x.txt", vec!["dir"; 2048].join("/"));
        assert!(long_path.len() > MAX_ENTRY_PATH_BYTES);
        assert!(sanitize_entry_path(&long_path).is_err());
    }

    #[test]
    fn prepare_entry_path_keeps_every_accepted_name_under_the_root() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-quota-prepare").expect("scratch");
        let root: &Path = scratch.path();
        std::fs::create_dir_all(root).expect("root");
        let root_real: PathBuf = std::fs::canonicalize(root).expect("canonical root");
        for (name, verdict) in HOSTILE_ENTRY_NAMES {
            let prepared: Result<PathBuf> = prepare_entry_path(root, name);
            match verdict {
                HostileNameVerdict::Refused => assert!(
                    matches!(prepared, Err(Error::UnsafeEntryPath(_))),
                    "`{name}` must be refused before any write, got {prepared:?}"
                ),
                HostileNameVerdict::ContainedWrite => {
                    let path: PathBuf =
                        prepared.unwrap_or_else(|e: Error| panic!("`{name}` prepare: {e}"));
                    std::fs::write(&path, b"payload").expect("write inside root");
                    let written_real: PathBuf =
                        std::fs::canonicalize(&path).expect("canonical written path");
                    assert!(
                        written_real.starts_with(&root_real),
                        "`{name}` resolved to {written_real:?} outside {root_real:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn resolved_within_rejects_a_sibling_of_the_root() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-quota-resolved").expect("scratch");
        let root: PathBuf = scratch.path().join("root");
        let sibling: PathBuf = scratch.path().join("sibling");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&sibling).expect("sibling");
        assert!(resolved_within(&root, &root).expect("self"));
        assert!(resolved_within(&root, &root.join("inner")).is_err());
        std::fs::create_dir_all(root.join("inner")).expect("inner");
        assert!(resolved_within(&root, &root.join("inner")).expect("inner"));
        assert!(!resolved_within(&root, &sibling).expect("sibling"));
        assert!(
            !resolved_within(&root, scratch.path()).expect("parent"),
            "the root's own parent must not count as contained"
        );
    }

    #[test]
    fn prepare_entry_path_refuses_a_directory_symlink_escape() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-quota-symlink").expect("scratch");
        let root: PathBuf = scratch.path().join("root");
        let outside: PathBuf = scratch.path().join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        let link: PathBuf = root.join("link");
        if !create_dir_symlink(&outside, &link) {
            assert!(
                !resolved_within(&root, &outside).expect("containment verdict"),
                "the containment check must reject a directory outside the root"
            );
            return;
        }
        let err: Error =
            prepare_entry_path(&root, "link/escape.txt").expect_err("symlinked parent must refuse");
        assert!(matches!(err, Error::UnsafeEntryPath(_)), "got {err:?}");
        assert!(
            !outside.join("escape.txt").exists(),
            "nothing may land through the link"
        );
    }

    #[cfg(unix)]
    fn create_dir_symlink(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn create_dir_symlink(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }

    #[test]
    fn sanitize_rejects_parent_escape() {
        assert!(sanitize_entry_path("../etc/passwd").is_err());
        assert!(sanitize_entry_path("sub/../bad").is_err());
        assert!(sanitize_entry_path("a/../../b").is_err());
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert!(sanitize_entry_path("").is_err());
        assert!(sanitize_entry_path("///").is_err());
    }

    #[test]
    fn sanitize_rejects_absolute_and_drive_prefixed_paths() {
        assert!(sanitize_entry_path("/etc/passwd").is_err());
        assert!(sanitize_entry_path("C:/Windows/win.ini").is_err());
        assert!(sanitize_entry_path("C:\\Windows\\win.ini").is_err());
        assert!(sanitize_entry_path("dir/file.txt:stream").is_err());
    }

    #[test]
    fn sanitize_normalizes_backslashes() {
        let cleaned: String = sanitize_entry_path("a\\b\\c.txt").expect("ok");
        assert_eq!(cleaned, "a/b/c.txt");
    }

    #[test]
    fn sanitize_passes_normal() {
        let cleaned: String = sanitize_entry_path("pkg/mod.pyc").expect("ok");
        assert_eq!(cleaned, "pkg/mod.pyc");
    }

    #[test]
    fn quota_per_entry_ratio_caps_at_100() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
        let err: Error = g.admit_entry("bomb", 200, 1).expect_err("must reject");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn quota_aggregate_ratio_caps_at_10() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
        g.admit_entry("a", 100, 50).expect("ok");
        let err: Error = g.admit_entry("b", 800, 5).expect_err("aggregate ratio");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn quota_admits_normal_traffic() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
        g.admit_entry("a.py", 1024, 512).expect("ok");
        g.admit_entry("b.py", 2048, 1024).expect("ok");
        assert_eq!(g.report().entries_accepted, 2);
    }

    #[test]
    fn quota_unrestricted_admits_anything() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::unrestricted());
        g.admit_entry("huge", 1 << 30, 1).expect("unrestricted ok");
    }

    #[test]
    fn bounded_prealloc_clamps_huge_declared_sizes() {
        assert_eq!(bounded_prealloc(0), 0);
        assert_eq!(bounded_prealloc(1024), 1024);
        assert_eq!(
            bounded_prealloc(MAX_ENTRY_PREALLOC as u64),
            MAX_ENTRY_PREALLOC
        );
        assert_eq!(bounded_prealloc(4 * 1024 * 1024 * 1024), MAX_ENTRY_PREALLOC);
        assert_eq!(bounded_prealloc(u64::MAX), MAX_ENTRY_PREALLOC);
    }

    #[test]
    fn bounded_entry_read_accepts_exact_cap() {
        let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(b"abc");
        let bytes: Vec<u8> = read_entry_to_limit(&mut reader, "entry.bin", 3).expect("read");
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn bounded_entry_read_rejects_over_cap() {
        let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(b"abcd");
        let err: Error =
            read_entry_to_limit(&mut reader, "entry.bin", 3).expect_err("over-cap read must fail");
        assert!(matches!(
            err,
            Error::QuotaExceeded { entry, reason }
                if entry == "entry.bin" && reason.contains("read cap")
        ));
    }
}
