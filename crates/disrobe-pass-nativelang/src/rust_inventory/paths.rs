use std::collections::BTreeMap;

use object::read::File as ObjectFile;
use object::{Object as _, ObjectSection as _, SectionKind};
use serde::Serialize;

use super::Evidence;
use super::releases::release_for_commit;
use crate::image::ImageKind;

const MAX_PATH_BYTES: usize = 1024;
const MAX_PATH_HITS: usize = 1 << 18;
const MAX_CRATES: usize = 16_384;
const MAX_RUSTC_COMMITS: usize = 256;
const MAX_LOCAL_PATHS: usize = 16_384;
const MAX_START_CANDIDATES: usize = 32;
const MAX_DYNAMIC_RELOCATIONS: usize = 1 << 24;
const MAX_MAPPED_SECTIONS: usize = 4096;
const MAX_POINTER_SCAN_BYTES: usize = 512 * 1024 * 1024;
const MAX_CRATE_NAME_BYTES: usize = 64;
const COMMIT_HEX_LEN: usize = 40;
const CARGO_HASH_HEX_LEN: usize = 16;
const MIN_REVISION_HEX_LEN: usize = 7;
const MACHO_CHAINED_TARGET_MASK: u64 = (1 << 36) - 1;
const RUSTC_PREFIX: &[u8] = b"/rustc/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RustcCommit {
    pub commit: String,
    pub release: Option<String>,
    pub occurrences: u64,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathStart {
    LocationRecord,
    PrintableRun,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CrateSource {
    Registry {
        index: String,
    },
    Git {
        repository: String,
        url_hash: String,
        revision: String,
        directory: Option<String>,
    },
    Vendored {
        root: String,
    },
    Path {
        root: String,
    },
    Workspace {
        root: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveredCrate {
    pub name: Option<String>,
    pub version: Option<String>,
    pub source: CrateSource,
    pub path_start: Option<PathStart>,
    pub occurrences: u64,
    pub evidence: Evidence,
}

#[derive(Debug, Default)]
pub(super) struct PathScan {
    pub(super) rustc: Vec<RustcCommit>,
    pub(super) crates: Vec<RecoveredCrate>,
    pub(super) truncated_paths: bool,
    pub(super) truncated_crates: bool,
    pub(super) truncated_commits: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CrateKey {
    name: Option<String>,
    version: Option<String>,
    source: CrateSource,
}

#[derive(Debug)]
struct Tally {
    occurrences: u64,
    evidence: Evidence,
    path_start: Option<PathStart>,
}

#[derive(Debug, Clone, Copy)]
struct Component {
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, Copy)]
struct LocalPath {
    run_start: usize,
    end: usize,
    src: usize,
    directory: Option<Component>,
    vendored: bool,
}

#[derive(Debug, Default)]
struct Collector {
    commits: BTreeMap<String, (u64, Evidence)>,
    crates: BTreeMap<CrateKey, Tally>,
    locals: Vec<LocalPath>,
    truncated_paths: bool,
    truncated_crates: bool,
    truncated_commits: bool,
}

impl Collector {
    fn commit(&mut self, commit: &str, evidence: Evidence) {
        if let Some((occurrences, _)) = self.commits.get_mut(commit) {
            *occurrences = occurrences.saturating_add(1);
            return;
        }
        if self.commits.len() >= MAX_RUSTC_COMMITS {
            self.truncated_commits = true;
            return;
        }
        self.commits.insert(commit.to_owned(), (1, evidence));
    }

    fn record(&mut self, key: CrateKey, evidence: Evidence, path_start: Option<PathStart>) {
        if let Some(tally) = self.crates.get_mut(&key) {
            tally.occurrences = tally.occurrences.saturating_add(1);
            return;
        }
        if self.crates.len() >= MAX_CRATES {
            self.truncated_crates = true;
            return;
        }
        self.crates.insert(
            key,
            Tally {
                occurrences: 1,
                evidence,
                path_start,
            },
        );
    }
}

pub(super) fn scan(raw: &[u8], file: &ObjectFile<'_>, container: ImageKind) -> PathScan {
    let mut collector: Collector = Collector::default();
    let mut hits: usize = 0;
    let mut cursor: usize = 0;
    while let Some(dot) = find_rs_suffix(raw, cursor) {
        cursor = dot + 1;
        let end: usize = dot + 3;
        if raw
            .get(end)
            .is_some_and(|byte: &u8| is_identifier_byte(*byte))
        {
            continue;
        }
        let start: usize = run_start(raw, dot);
        if !raw[start..end].iter().copied().any(is_separator) {
            continue;
        }
        hits += 1;
        if hits > MAX_PATH_HITS {
            collector.truncated_paths = true;
            break;
        }
        classify(raw, start, end, &mut collector);
    }
    let locals: Vec<LocalPath> = std::mem::take(&mut collector.locals);
    let resolved: Vec<Option<usize>> = resolve_starts(raw, file, container, &locals);
    for (local, resolved_start) in locals.iter().zip(resolved) {
        record_local(raw, local, resolved_start, &mut collector);
    }
    PathScan {
        rustc: collector
            .commits
            .into_iter()
            .map(
                |(commit, (occurrences, evidence)): (String, (u64, Evidence))| RustcCommit {
                    release: release_for_commit(&commit).map(str::to_owned),
                    commit,
                    occurrences,
                    evidence,
                },
            )
            .collect(),
        crates: collector
            .crates
            .into_iter()
            .map(|(key, tally): (CrateKey, Tally)| RecoveredCrate {
                name: key.name,
                version: key.version,
                source: key.source,
                path_start: tally.path_start,
                occurrences: tally.occurrences,
                evidence: tally.evidence,
            })
            .collect(),
        truncated_paths: collector.truncated_paths,
        truncated_crates: collector.truncated_crates,
        truncated_commits: collector.truncated_commits,
    }
}

fn find_rs_suffix(raw: &[u8], from: usize) -> Option<usize> {
    raw.get(from..)?
        .windows(3)
        .position(|window: &[u8]| window == b".rs")
        .map(|position: usize| from + position)
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

const fn is_separator(byte: u8) -> bool {
    byte == b'/' || byte == b'\\'
}

const fn is_path_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e) && !matches!(byte, b'"' | b'*' | b'<' | b'>' | b'?' | b'|')
}

fn run_start(raw: &[u8], dot: usize) -> usize {
    let floor: usize = dot.saturating_sub(MAX_PATH_BYTES);
    let mut start: usize = dot;
    while start > floor && is_path_byte(raw[start - 1]) {
        start -= 1;
    }
    start
}

fn components(run: &[u8]) -> Vec<Component> {
    let mut out: Vec<Component> = Vec::new();
    let mut start: usize = 0;
    for (index, byte) in run.iter().enumerate() {
        if is_separator(*byte) {
            if index > start {
                out.push(Component { start, end: index });
            }
            start = index + 1;
        }
    }
    if run.len() > start {
        out.push(Component {
            start,
            end: run.len(),
        });
    }
    out
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn classify(raw: &[u8], start: usize, end: usize, collector: &mut Collector) {
    let run: &[u8] = &raw[start..end];
    if let Some((at, commit)) = rustc_commit(run) {
        collector.commit(
            commit,
            Evidence {
                offset: (start + at) as u64,
                text: text(&run[at..]),
            },
        );
        return;
    }
    let parts: Vec<Component> = components(run);
    let name = |index: usize| -> &[u8] {
        parts
            .get(index)
            .map_or(&[][..], |part: &Component| &run[part.start..part.end])
    };
    let last: usize = parts.len().saturating_sub(1);
    for index in 0..parts.len() {
        if (name(index) == b"rustlib" && name(index + 1) == b"src" && name(index + 2) == b"rust")
            || (name(index) == b"rust"
                && name(index + 1) == b"deps"
                && split_crate_directory(name(index + 2)).is_some())
        {
            return;
        }
        if name(index) == b"registry"
            && name(index + 1) == b"src"
            && index + 3 < last
            && split_hashed_directory(name(index + 2)).is_some()
            && let Some((crate_name, version)) = split_crate_directory(name(index + 3))
        {
            let at: usize = parts[index].start;
            collector.record(
                CrateKey {
                    name: Some(crate_name.to_owned()),
                    version: Some(version.to_owned()),
                    source: CrateSource::Registry {
                        index: text(name(index + 2)),
                    },
                },
                Evidence {
                    offset: (start + at) as u64,
                    text: text(&run[at..]),
                },
                None,
            );
            return;
        }
        if name(index) == b"git"
            && name(index + 1) == b"checkouts"
            && index + 3 < last
            && let Some((repository, url_hash)) = split_hashed_directory(name(index + 2))
            && is_revision(name(index + 3))
        {
            let src: Option<usize> =
                (index + 4..last).find(|candidate: &usize| name(*candidate) == b"src");
            let directory: Option<String> = src
                .filter(|src: &usize| *src > index + 4)
                .map(|src: usize| text(&run[parts[index + 4].start..parts[src - 1].end]));
            let crate_name: String = src
                .filter(|src: &usize| *src > index + 4)
                .map_or_else(|| repository.to_owned(), |src: usize| text(name(src - 1)));
            let at: usize = parts[index].start;
            collector.record(
                CrateKey {
                    name: Some(crate_name),
                    version: None,
                    source: CrateSource::Git {
                        repository: repository.to_owned(),
                        url_hash: url_hash.to_owned(),
                        revision: text(name(index + 3)),
                        directory,
                    },
                },
                Evidence {
                    offset: (start + at) as u64,
                    text: text(&run[at..]),
                },
                None,
            );
            return;
        }
    }
    let Some(src) = (0..last).rev().find(|index: &usize| name(*index) == b"src") else {
        return;
    };
    if collector.locals.len() >= MAX_LOCAL_PATHS {
        collector.truncated_paths = true;
        return;
    }
    let directory: Option<Component> = src.checked_sub(1).map(|index: usize| Component {
        start: start + parts[index].start,
        end: start + parts[index].end,
    });
    let vendored: bool = src >= 2 && name(src - 2) == b"vendor";
    collector.locals.push(LocalPath {
        run_start: start,
        end,
        src: start + parts[src].start,
        directory,
        vendored,
    });
}

fn rustc_commit(run: &[u8]) -> Option<(usize, &str)> {
    run.windows(RUSTC_PREFIX.len())
        .enumerate()
        .filter(|(_, window): &(usize, &[u8])| *window == RUSTC_PREFIX)
        .find_map(|(at, _): (usize, &[u8])| {
            let hex_start: usize = at + RUSTC_PREFIX.len();
            let hex: &[u8] = run.get(hex_start..hex_start + COMMIT_HEX_LEN)?;
            let separator: u8 = *run.get(hex_start + COMMIT_HEX_LEN)?;
            (is_lower_hex(hex) && is_separator(separator))
                .then(|| {
                    std::str::from_utf8(hex)
                        .ok()
                        .map(|commit: &str| (at, commit))
                })
                .flatten()
        })
}

fn is_lower_hex(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte: &u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_revision(bytes: &[u8]) -> bool {
    (MIN_REVISION_HEX_LEN..=COMMIT_HEX_LEN).contains(&bytes.len()) && is_lower_hex(bytes)
}

fn split_hashed_directory(directory: &[u8]) -> Option<(&str, &str)> {
    let directory: &str = std::str::from_utf8(directory).ok()?;
    let (prefix, hash): (&str, &str) = directory.rsplit_once('-')?;
    (!prefix.is_empty()
        && hash.len() == CARGO_HASH_HEX_LEN
        && is_lower_hex(hash.as_bytes())
        && prefix
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    .then_some((prefix, hash))
}

fn split_crate_directory(directory: &[u8]) -> Option<(&str, &str)> {
    let directory: &str = std::str::from_utf8(directory).ok()?;
    directory
        .char_indices()
        .filter(|(_, character): &(usize, char)| *character == '-')
        .map(|(index, _): (usize, char)| (&directory[..index], &directory[index + 1..]))
        .find(|(name, version): &(&str, &str)| is_crate_name(name) && is_semver(version))
}

fn is_crate_name(name: &str) -> bool {
    name.len() <= MAX_CRATE_NAME_BYTES
        && name
            .bytes()
            .next()
            .is_some_and(|byte: u8| byte.is_ascii_alphabetic())
        && name
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn is_semver(version: &str) -> bool {
    let (rest, build): (&str, Option<&str>) = version
        .split_once('+')
        .map_or((version, None), |(rest, build): (&str, &str)| {
            (rest, Some(build))
        });
    let (core, pre): (&str, Option<&str>) = rest
        .split_once('-')
        .map_or((rest, None), |(core, pre): (&str, &str)| (core, Some(pre)));
    let numeric = |part: Option<&str>| -> bool {
        part.is_some_and(|part: &str| {
            !part.is_empty()
                && part.bytes().all(|byte: u8| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'))
        })
    };
    let mut parts: std::str::Split<'_, char> = core.split('.');
    numeric(parts.next())
        && numeric(parts.next())
        && numeric(parts.next())
        && parts.next().is_none()
        && pre.is_none_or(is_identifier_list)
        && build.is_none_or(is_identifier_list)
}

fn is_identifier_list(text: &str) -> bool {
    text.split('.').all(|identifier: &str| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

const fn is_start_boundary(raw: &[u8], run_start: usize, at: usize) -> bool {
    at == run_start
        || is_separator(raw[at])
        || !(raw[at - 1].is_ascii_alphanumeric()
            || matches!(raw[at - 1], b'_' | b'.' | b'-' | b':'))
}

#[derive(Debug, Clone, Copy)]
struct MappedRange {
    offset: u64,
    size: u64,
    address: u64,
}

#[derive(Debug)]
struct AddressSpace {
    by_offset: Vec<MappedRange>,
    by_address: Vec<MappedRange>,
    width: usize,
    little_endian: bool,
}

impl AddressSpace {
    fn new(file: &ObjectFile<'_>) -> Self {
        let mut by_offset: Vec<MappedRange> = file
            .sections()
            .take(MAX_MAPPED_SECTIONS)
            .filter(|section: &object::read::Section<'_, '_, &[u8]>| section.address() != 0)
            .filter_map(|section: object::read::Section<'_, '_, &[u8]>| {
                let (offset, size): (u64, u64) = section.file_range()?;
                (size > 0).then_some(MappedRange {
                    offset,
                    size,
                    address: section.address(),
                })
            })
            .collect();
        by_offset.sort_by_key(|range: &MappedRange| range.offset);
        let mut by_address: Vec<MappedRange> = by_offset.clone();
        by_address.sort_by_key(|range: &MappedRange| range.address);
        Self {
            by_offset,
            by_address,
            width: if file.is_64() { 8 } else { 4 },
            little_endian: file.is_little_endian(),
        }
    }

    fn address_of(&self, offset: usize) -> Option<u64> {
        let offset: u64 = offset as u64;
        let index: usize = self
            .by_offset
            .partition_point(|range: &MappedRange| range.offset <= offset)
            .checked_sub(1)?;
        let range: &MappedRange = &self.by_offset[index];
        (offset - range.offset < range.size)
            .then(|| range.address.checked_add(offset - range.offset))
            .flatten()
    }

    fn offset_of(&self, address: u64) -> Option<usize> {
        let index: usize = self
            .by_address
            .partition_point(|range: &MappedRange| range.address <= address)
            .checked_sub(1)?;
        let range: &MappedRange = &self.by_address[index];
        (address - range.address < range.size)
            .then(|| range.offset.checked_add(address - range.address))
            .flatten()
            .and_then(|offset: u64| usize::try_from(offset).ok())
    }

    fn word(&self, bytes: &[u8], at: usize) -> Option<u64> {
        let slice: &[u8] = bytes.get(at..at.checked_add(self.width)?)?;
        let mut buffer: [u8; 8] = [0; 8];
        if self.little_endian {
            buffer[..self.width].copy_from_slice(slice);
            Some(u64::from_le_bytes(buffer))
        } else {
            buffer[8 - self.width..].copy_from_slice(slice);
            Some(u64::from_be_bytes(buffer))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct StartCandidate {
    local: usize,
    start: usize,
    length: u64,
}

fn resolve_starts(
    raw: &[u8],
    file: &ObjectFile<'_>,
    container: ImageKind,
    locals: &[LocalPath],
) -> Vec<Option<usize>> {
    let mut resolved: Vec<Option<usize>> = vec![None; locals.len()];
    let space: AddressSpace = AddressSpace::new(file);
    let mut wanted: BTreeMap<u64, Vec<StartCandidate>> = BTreeMap::new();
    for (index, local) in locals.iter().enumerate() {
        let limit: usize = local
            .directory
            .map_or(local.src, |directory: Component| directory.start);
        for start in (local.run_start..=limit)
            .filter(|at: &usize| is_start_boundary(raw, local.run_start, *at))
            .take(MAX_START_CANDIDATES)
        {
            if let Some(address) = space.address_of(start) {
                wanted.entry(address).or_default().push(StartCandidate {
                    local: index,
                    start,
                    length: (local.end - start) as u64,
                });
            }
        }
    }
    let (Some(lowest), Some(highest)): (Option<u64>, Option<u64>) = (
        wanted.keys().next().copied(),
        wanted.keys().next_back().copied(),
    ) else {
        return resolved;
    };
    let mut accept = |target: u64, length: Option<u64>| {
        if target < lowest || target > highest {
            return;
        }
        let (Some(candidates), Some(length)) = (wanted.get(&target), length) else {
            return;
        };
        for candidate in candidates
            .iter()
            .filter(|candidate: &&StartCandidate| candidate.length == length)
        {
            let slot: &mut Option<usize> = &mut resolved[candidate.local];
            *slot = Some(slot.map_or(candidate.start, |current: usize| {
                current.min(candidate.start)
            }));
        }
    };
    let base: u64 = file.relative_address_base();
    let mut scan_budget: usize = MAX_POINTER_SCAN_BYTES;
    for section in file.sections().take(MAX_MAPPED_SECTIONS) {
        if !matches!(
            section.kind(),
            SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::ReadOnlyDataWithRel
        ) {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        let Some(remaining) = scan_budget.checked_sub(data.len()) else {
            break;
        };
        scan_budget = remaining;
        let mut at: usize = 0;
        while at + 2 * space.width <= data.len() {
            if let Some(value) = space.word(data, at) {
                let length: Option<u64> = space.word(data, at + space.width);
                accept(value, length);
                if container == ImageKind::MachO && value > MACHO_CHAINED_TARGET_MASK {
                    let target: u64 = value & MACHO_CHAINED_TARGET_MASK;
                    accept(target, length);
                    accept(base.wrapping_add(target), length);
                }
            }
            at += space.width;
        }
    }
    if container == ImageKind::Elf
        && let Some(relocations) = file.dynamic_relocations()
    {
        for (address, relocation) in relocations.take(MAX_DYNAMIC_RELOCATIONS) {
            if relocation.has_implicit_addend() {
                continue;
            }
            let length: Option<u64> = address
                .checked_add(space.width as u64)
                .and_then(|length_address: u64| space.offset_of(length_address))
                .and_then(|offset: usize| space.word(raw, offset));
            accept(relocation.addend() as u64, length);
        }
    }
    resolved
}

fn record_local(
    raw: &[u8],
    local: &LocalPath,
    resolved_start: Option<usize>,
    collector: &mut Collector,
) {
    let start: usize = resolved_start.unwrap_or(local.run_start);
    let path_start: PathStart = if resolved_start.is_some() {
        PathStart::LocationRecord
    } else {
        PathStart::PrintableRun
    };
    let root_end: usize = local.directory.map_or_else(
        || local.src.saturating_sub(1).max(start),
        |directory: Component| directory.end,
    );
    let root: String = text(&raw[start..root_end.max(start)]);
    let directory: Option<&[u8]> = local
        .directory
        .map(|directory: Component| &raw[directory.start..directory.end]);
    let (name, version): (Option<String>, Option<String>) = if local.vendored {
        directory.map_or((None, None), |directory: &[u8]| {
            split_crate_directory(directory).map_or_else(
                || (Some(text(directory)), None),
                |(name, version): (&str, &str)| (Some(name.to_owned()), Some(version.to_owned())),
            )
        })
    } else {
        (directory.map(text), None)
    };
    let absolute: bool = root.starts_with(['/', '\\'])
        || (root.len() >= 3
            && root.as_bytes()[0].is_ascii_alphabetic()
            && root.as_bytes()[1] == b':'
            && is_separator(root.as_bytes()[2]));
    let source: CrateSource = if local.vendored {
        CrateSource::Vendored { root }
    } else if absolute {
        CrateSource::Path { root }
    } else {
        CrateSource::Workspace { root }
    };
    collector.record(
        CrateKey {
            name,
            version,
            source,
        },
        Evidence {
            offset: start as u64,
            text: text(&raw[start..local.end]),
        },
        Some(path_start),
    );
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn crate_directories_split_at_the_first_semver_suffix() {
        assert_eq!(
            split_crate_directory(b"regex-automata-0.4.18"),
            Some(("regex-automata", "0.4.18"))
        );
        assert_eq!(
            split_crate_directory(b"windows-sys-0.59.0-rc.1+build.2"),
            Some(("windows-sys", "0.59.0-rc.1+build.2"))
        );
        assert_eq!(split_crate_directory(b"regex-01.2.3"), None);
        assert_eq!(split_crate_directory(b"regex-1.2"), None);
        assert_eq!(split_crate_directory(b"-1.2.3"), None);
    }

    #[test]
    fn hashed_directories_need_sixteen_lower_hex_digits() {
        assert_eq!(
            split_hashed_directory(b"index.crates.io-1949cf8c6b5b557f"),
            Some(("index.crates.io", "1949cf8c6b5b557f"))
        );
        assert_eq!(
            split_hashed_directory(b"index.crates.io-1949cf8c6b5b557"),
            None
        );
        assert_eq!(
            split_hashed_directory(b"index.crates.io-1949CF8C6B5B557F"),
            None
        );
    }

    #[test]
    fn rustc_commit_needs_forty_hex_digits_and_a_separator() {
        let commit: &str = "59807616e1fa2540724bfbac14d7976d7e4a3860";
        let forward: String = format!("x/rustc/{commit}/library/core/src/lib.rs");
        let mixed: String = format!("/rustc/{commit}\\library\\core\\src\\lib.rs");
        let short: String = format!("/rustc/{}/library/core/src/lib.rs", &commit[..39]);
        assert_eq!(rustc_commit(forward.as_bytes()), Some((1, commit)));
        assert_eq!(rustc_commit(mixed.as_bytes()), Some((0, commit)));
        assert_eq!(rustc_commit(short.as_bytes()), None);
    }

    #[test]
    fn registry_paths_match_under_any_cargo_home() {
        let homes: [&[u8]; 4] = [
            b"/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.228/src/de/mod.rs",
            b"/opt/rust/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.228/src/lib.rs",
            b"C:\\cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\serde-1.0.228\\src\\ser\\mod.rs",
            b"msg/root/.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\serde-1.0.228\\src\\lib.rs",
        ];
        let mut collector: Collector = Collector::default();
        for home in homes {
            let mut raw: Vec<u8> = vec![0];
            raw.extend_from_slice(home);
            raw.push(0);
            classify(&raw, 1, raw.len() - 1, &mut collector);
        }
        let entries: Vec<(&CrateKey, u64)> = collector
            .crates
            .iter()
            .map(|(key, tally): (&CrateKey, &Tally)| (key, tally.occurrences))
            .collect();
        assert_eq!(
            entries,
            vec![(
                &CrateKey {
                    name: Some("serde".to_owned()),
                    version: Some("1.0.228".to_owned()),
                    source: CrateSource::Registry {
                        index: "index.crates.io-1949cf8c6b5b557f".to_owned(),
                    },
                },
                4
            )]
        );
        assert!(collector.locals.is_empty());
    }
}
