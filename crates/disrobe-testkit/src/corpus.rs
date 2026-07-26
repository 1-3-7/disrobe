use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{StressError, io_error};
use crate::mutate::MutationKind;
use crate::wire::MAX_CORPUS_ENTRY_BYTES;

pub type CheckFn = fn(&StressCase<'_>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusEntry {
    name: String,
    bytes: Vec<u8>,
}

impl CorpusEntry {
    pub fn new(name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            bytes: bytes.into(),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StressCase<'a> {
    entry: &'a str,
    case_index: usize,
    case_seed: u64,
    mutation: MutationKind,
    bytes: &'a [u8],
}

impl<'a> StressCase<'a> {
    #[must_use]
    pub const fn new(
        entry: &'a str,
        case_index: usize,
        case_seed: u64,
        mutation: MutationKind,
        bytes: &'a [u8],
    ) -> Self {
        Self {
            entry,
            case_index,
            case_seed,
            mutation,
            bytes,
        }
    }

    #[must_use]
    pub const fn entry(&self) -> &'a str {
        self.entry
    }

    #[must_use]
    pub const fn case_index(&self) -> usize {
        self.case_index
    }

    #[must_use]
    pub const fn case_seed(&self) -> u64 {
        self.case_seed
    }

    #[must_use]
    pub const fn mutation(&self) -> MutationKind {
        self.mutation
    }

    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub fn replay_hint(&self) -> String {
        format!(
            "entry `{}` seed {:#018x} mutation {}",
            self.entry, self.case_seed, self.mutation
        )
    }
}

pub trait CorpusSource {
    fn into_entries(self) -> Result<Vec<CorpusEntry>, StressError>;
}

impl CorpusSource for Vec<CorpusEntry> {
    fn into_entries(self) -> Result<Vec<CorpusEntry>, StressError> {
        Ok(self)
    }
}

impl CorpusSource for Result<Vec<CorpusEntry>, StressError> {
    fn into_entries(self) -> Result<Vec<CorpusEntry>, StressError> {
        self
    }
}

pub fn read_corpus_dir(dir: &Path) -> Result<Vec<CorpusEntry>, StressError> {
    let listing: std::fs::ReadDir = std::fs::read_dir(dir).map_err(|error: std::io::Error| {
        io_error(format!("reading corpus directory {}", dir.display()), error)
    })?;
    let limit: u64 = u64::try_from(MAX_CORPUS_ENTRY_BYTES).unwrap_or(u64::MAX);
    let mut entries: Vec<CorpusEntry> = Vec::new();
    for item in listing {
        let item: std::fs::DirEntry = item.map_err(|error: std::io::Error| {
            io_error(format!("walking corpus directory {}", dir.display()), error)
        })?;
        let path: std::path::PathBuf = item.path();
        let metadata: std::fs::Metadata =
            path.symlink_metadata().map_err(|error: std::io::Error| {
                io_error(format!("reading metadata of {}", path.display()), error)
            })?;
        if !metadata.is_file() {
            continue;
        }
        let name: String = item.file_name().to_string_lossy().into_owned();
        if metadata.len() > limit {
            return Err(StressError::CorpusEntryTooLarge {
                entry: name,
                bytes: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
                limit: MAX_CORPUS_ENTRY_BYTES,
            });
        }
        let bytes: Vec<u8> = std::fs::read(&path).map_err(|error: std::io::Error| {
            io_error(format!("reading corpus entry {}", path.display()), error)
        })?;
        entries.push(CorpusEntry::new(name, bytes));
    }
    entries.sort_by(|left: &CorpusEntry, right: &CorpusEntry| left.name.cmp(&right.name));
    Ok(entries)
}

pub(crate) fn validate_corpus(corpus: &[CorpusEntry]) -> Result<(), StressError> {
    let mut first_seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, entry) in corpus.iter().enumerate() {
        if entry.bytes.len() > MAX_CORPUS_ENTRY_BYTES {
            return Err(StressError::CorpusEntryTooLarge {
                entry: entry.name.clone(),
                bytes: entry.bytes.len(),
                limit: MAX_CORPUS_ENTRY_BYTES,
            });
        }
        if let Some(first_index) = first_seen.insert(entry.name.as_str(), index) {
            return Err(StressError::DuplicateCorpusEntry {
                name: entry.name.clone(),
                first_index,
                second_index: index,
            });
        }
    }
    Ok(())
}

pub(crate) fn entry_for_case<'a>(
    corpus: &'a [CorpusEntry],
    order: &[usize],
    cases_per_input: usize,
    case_index: usize,
) -> Result<&'a CorpusEntry, StressError> {
    let slot: usize =
        case_index
            .checked_div(cases_per_input)
            .ok_or_else(|| StressError::Inconsistent {
                detail: "cases_per_input is zero".to_owned(),
            })?;
    order
        .get(slot)
        .and_then(|index: &usize| corpus.get(*index))
        .ok_or_else(|| StressError::Inconsistent {
            detail: format!(
                "case {case_index} maps to corpus slot {slot} of {}",
                order.len()
            ),
        })
}

pub(crate) fn ordered_indices(corpus: &[CorpusEntry]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..corpus.len()).collect();
    order.sort_by(|left: &usize, right: &usize| {
        let left_name: &str = corpus.get(*left).map_or("", CorpusEntry::name);
        let right_name: &str = corpus.get(*right).map_or("", CorpusEntry::name);
        left_name
            .as_bytes()
            .cmp(right_name.as_bytes())
            .then_with(|| left.cmp(right))
    });
    order
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{
        CorpusEntry, MAX_CORPUS_ENTRY_BYTES, StressError, ordered_indices, validate_corpus,
    };

    #[test]
    fn entries_are_ordered_by_name_regardless_of_caller_order() {
        let corpus: Vec<CorpusEntry> = vec![
            CorpusEntry::new("zeta", b"z".to_vec()),
            CorpusEntry::new("alpha", b"a".to_vec()),
            CorpusEntry::new("mid", b"m".to_vec()),
        ];
        assert_eq!(ordered_indices(&corpus), vec![1, 2, 0]);
    }

    #[test]
    fn a_duplicate_name_is_rejected_so_a_replay_identity_stays_unique() {
        let corpus: Vec<CorpusEntry> = vec![
            CorpusEntry::new("same", b"first".to_vec()),
            CorpusEntry::new("other", b"middle".to_vec()),
            CorpusEntry::new("same", b"second".to_vec()),
        ];
        match validate_corpus(&corpus) {
            Err(StressError::DuplicateCorpusEntry {
                name,
                first_index,
                second_index,
            }) => {
                assert_eq!(name, "same");
                assert_eq!(first_index, 0);
                assert_eq!(second_index, 2);
            }
            other => panic!("a duplicate corpus name must be refused, got {other:?}"),
        }
    }

    #[test]
    fn distinct_names_within_the_entry_limit_validate() {
        let corpus: Vec<CorpusEntry> = vec![
            CorpusEntry::new("alpha", b"a".to_vec()),
            CorpusEntry::new("beta", b"b".to_vec()),
        ];
        assert!(validate_corpus(&corpus).is_ok());
        assert!(validate_corpus(&[]).is_ok());
    }

    #[test]
    fn an_entry_over_the_corpus_limit_is_refused_before_any_case_runs() {
        let corpus: Vec<CorpusEntry> = vec![CorpusEntry::new(
            "oversized",
            vec![0u8; MAX_CORPUS_ENTRY_BYTES + 1],
        )];
        match validate_corpus(&corpus) {
            Err(StressError::CorpusEntryTooLarge { entry, limit, .. }) => {
                assert_eq!(entry, "oversized");
                assert_eq!(limit, MAX_CORPUS_ENTRY_BYTES);
            }
            other => panic!("an oversized corpus entry must be refused, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_corpus_orders_to_nothing() {
        assert!(ordered_indices(&[]).is_empty());
    }
}
