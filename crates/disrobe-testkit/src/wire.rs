use std::ffi::OsString;
use std::io::{BufReader, BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};

use crate::error::{StressError, io_error};
use crate::mutate::MutationKind;

pub(crate) const BATCH_MAGIC: [u8; 8] = *b"DRTKBAT1";
pub(crate) const MAX_WIRE_CASE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_CORPUS_ENTRY_BYTES: usize = MAX_WIRE_CASE_BYTES / 4;
pub(crate) const MAX_ENTRY_NAME_BYTES: usize = 4096;
pub(crate) const PROGRESS_SUFFIX: &str = ".progress";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchRecord {
    pub(crate) case_index: usize,
    pub(crate) case_seed: u64,
    pub(crate) mutation: MutationKind,
    pub(crate) entry: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Batch {
    pub(crate) token: u64,
    pub(crate) records: Vec<BatchRecord>,
}

pub(crate) fn progress_path(batch_path: &Path) -> PathBuf {
    let mut raw: OsString = batch_path.as_os_str().to_owned();
    raw.push(PROGRESS_SUFFIX);
    PathBuf::from(raw)
}

pub(crate) fn write_batch(
    path: &Path,
    token: u64,
    records: &[BatchRecord],
) -> Result<(), StressError> {
    let count: u32 = u32::try_from(records.len()).map_err(|_| StressError::Inconsistent {
        detail: format!("{} cases do not fit a u32 batch header", records.len()),
    })?;
    let file: std::fs::File = std::fs::File::create(path).map_err(|error: std::io::Error| {
        io_error(format!("creating batch file {}", path.display()), error)
    })?;
    let mut writer: BufWriter<std::fs::File> = BufWriter::new(file);
    let mut encoded: Vec<u8> = Vec::new();
    encoded.extend_from_slice(&BATCH_MAGIC);
    encoded.extend_from_slice(&token.to_le_bytes());
    encoded.extend_from_slice(&count.to_le_bytes());
    for record in records {
        let name: &[u8] = record.entry.as_bytes();
        if name.len() > MAX_ENTRY_NAME_BYTES {
            return Err(StressError::Inconsistent {
                detail: format!(
                    "corpus entry name of {} bytes exceeds the {MAX_ENTRY_NAME_BYTES} byte limit",
                    name.len()
                ),
            });
        }
        if record.bytes.len() > MAX_WIRE_CASE_BYTES {
            return Err(StressError::MutatedCaseTooLarge {
                entry: record.entry.clone(),
                case_index: record.case_index,
                case_seed: record.case_seed,
                bytes: record.bytes.len(),
                limit: MAX_WIRE_CASE_BYTES,
            });
        }
        let case_index: u64 = u64::try_from(record.case_index).unwrap_or(u64::MAX);
        let name_len: u32 = u32::try_from(name.len()).unwrap_or(u32::MAX);
        let bytes_len: u32 = u32::try_from(record.bytes.len()).unwrap_or(u32::MAX);
        encoded.extend_from_slice(&case_index.to_le_bytes());
        encoded.extend_from_slice(&record.case_seed.to_le_bytes());
        encoded.push(record.mutation.to_wire());
        encoded.extend_from_slice(&name_len.to_le_bytes());
        encoded.extend_from_slice(name);
        encoded.extend_from_slice(&bytes_len.to_le_bytes());
        encoded.extend_from_slice(&record.bytes);
    }
    writer
        .write_all(&encoded)
        .and_then(|()| writer.flush())
        .map_err(|error: std::io::Error| {
            io_error(format!("writing batch file {}", path.display()), error)
        })
}

pub(crate) fn read_batch(path: &Path) -> std::io::Result<Batch> {
    let file: std::fs::File = std::fs::File::open(path)?;
    let mut reader: BufReader<std::fs::File> = BufReader::new(file);
    let mut magic: [u8; 8] = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if magic != BATCH_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "batch file magic does not match the stress protocol",
        ));
    }
    let token: u64 = read_u64(&mut reader)?;
    let count: usize = usize::try_from(read_u32(&mut reader)?).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "batch case count does not fit usize",
        )
    })?;
    let mut records: Vec<BatchRecord> = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let case_index: usize = usize::try_from(read_u64(&mut reader)?).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "batch case index does not fit usize",
            )
        })?;
        let case_seed: u64 = read_u64(&mut reader)?;
        let mut mutation_byte: [u8; 1] = [0u8; 1];
        reader.read_exact(&mut mutation_byte)?;
        let mutation: MutationKind =
            MutationKind::from_wire(mutation_byte[0]).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "batch record carries an unknown mutation kind",
                )
            })?;
        let name_len: u32 = read_u32(&mut reader)?;
        let name: Vec<u8> =
            read_bounded(&mut reader, name_len, MAX_ENTRY_NAME_BYTES, "entry name")?;
        let entry: String = String::from_utf8(name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "batch record carries a non-utf8 corpus entry name",
            )
        })?;
        let body_len: u32 = read_u32(&mut reader)?;
        let bytes: Vec<u8> = read_bounded(&mut reader, body_len, MAX_WIRE_CASE_BYTES, "case body")?;
        records.push(BatchRecord {
            case_index,
            case_seed,
            mutation,
            entry,
            bytes,
        });
    }
    let mut trailing: [u8; 1] = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "batch file carries bytes past its declared case count",
        ));
    }
    Ok(Batch { token, records })
}

fn read_u32(reader: &mut BufReader<std::fs::File>) -> std::io::Result<u32> {
    let mut raw: [u8; 4] = [0u8; 4];
    reader.read_exact(&mut raw)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(reader: &mut BufReader<std::fs::File>) -> std::io::Result<u64> {
    let mut raw: [u8; 8] = [0u8; 8];
    reader.read_exact(&mut raw)?;
    Ok(u64::from_le_bytes(raw))
}

fn read_bounded(
    reader: &mut BufReader<std::fs::File>,
    declared: u32,
    limit: usize,
    what: &str,
) -> std::io::Result<Vec<u8>> {
    let len: usize = usize::try_from(declared).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} length does not fit usize"),
        )
    })?;
    if len > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} length {len} exceeds the {limit} byte limit"),
        ));
    }
    let mut buffer: Vec<u8> = vec![0u8; len];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}

pub(crate) fn module_line(module_path: &str) -> String {
    format!("module {module_path}\n")
}

pub(crate) fn case_line(batch_offset: usize) -> String {
    format!("case {batch_offset}\n")
}

pub(crate) fn seal_line(token: u64, cases: usize) -> String {
    format!("seal {token:016x} {cases}\n")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Progress {
    Sealed {
        module: Option<String>,
        token: u64,
        sealed_cases: usize,
        completed: usize,
    },
    Unsealed {
        module: Option<String>,
        completed: usize,
    },
    Malformed {
        detail: String,
        completed: usize,
    },
}

pub(crate) fn parse_progress(content: &str) -> Progress {
    let mut completed: usize = 0;
    let mut module: Option<String> = None;
    let mut sealed: Option<(u64, usize)> = None;
    for raw in content.split_inclusive('\n') {
        if !raw.ends_with('\n') {
            break;
        }
        let line: &str = raw.trim_end_matches('\n').trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if sealed.is_some() {
            return Progress::Malformed {
                detail: format!("`{line}` follows the seal"),
                completed,
            };
        }
        let mut fields: core::str::SplitAsciiWhitespace<'_> = line.split_ascii_whitespace();
        match fields.next() {
            Some("module") => {
                let Some(path): Option<&str> = fields.next() else {
                    return Progress::Malformed {
                        detail: format!("`{line}` has no module path"),
                        completed,
                    };
                };
                if fields.next().is_some() {
                    return Progress::Malformed {
                        detail: format!("`{line}` carries unexpected trailing fields"),
                        completed,
                    };
                }
                if module.is_some() || completed != 0 {
                    return Progress::Malformed {
                        detail: format!("`{line}` does not open the record"),
                        completed,
                    };
                }
                module = Some(path.to_owned());
            }
            Some("case") => {
                let Some(index_text): Option<&str> = fields.next() else {
                    return Progress::Malformed {
                        detail: format!("`{line}` has no case index"),
                        completed,
                    };
                };
                let Ok(index): Result<usize, core::num::ParseIntError> =
                    index_text.parse::<usize>()
                else {
                    return Progress::Malformed {
                        detail: format!("`{line}` has an unparsable case index"),
                        completed,
                    };
                };
                if index != completed {
                    return Progress::Malformed {
                        detail: format!(
                            "case index {index} arrived where {completed} was expected"
                        ),
                        completed,
                    };
                }
                if fields.next().is_some() {
                    return Progress::Malformed {
                        detail: format!("`{line}` carries unexpected trailing fields"),
                        completed,
                    };
                }
                completed = completed.saturating_add(1);
            }
            Some("seal") => {
                let (Some(token_text), Some(count_text)): (Option<&str>, Option<&str>) =
                    (fields.next(), fields.next())
                else {
                    return Progress::Malformed {
                        detail: format!("`{line}` is not a complete seal"),
                        completed,
                    };
                };
                let Ok(token): Result<u64, core::num::ParseIntError> =
                    u64::from_str_radix(token_text, 16)
                else {
                    return Progress::Malformed {
                        detail: format!("`{line}` has an unparsable seal token"),
                        completed,
                    };
                };
                let Ok(count): Result<usize, core::num::ParseIntError> =
                    count_text.parse::<usize>()
                else {
                    return Progress::Malformed {
                        detail: format!("`{line}` has an unparsable seal count"),
                        completed,
                    };
                };
                if fields.next().is_some() {
                    return Progress::Malformed {
                        detail: format!("`{line}` carries unexpected trailing fields"),
                        completed,
                    };
                }
                sealed = Some((token, count));
            }
            _ => {
                return Progress::Malformed {
                    detail: format!("`{line}` is not a module, case or seal line"),
                    completed,
                };
            }
        }
    }
    match sealed {
        Some((token, sealed_cases)) => Progress::Sealed {
            module,
            token,
            sealed_cases,
            completed,
        },
        None => Progress::Unsealed { module, completed },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CORPUS_ENTRY_BYTES, MAX_WIRE_CASE_BYTES, Progress, case_line, module_line,
        parse_progress, progress_path, seal_line,
    };
    use std::path::{Path, PathBuf};

    const MODULE: &str = "suite::worker";

    fn sealed_record(cases: usize, token: u64) -> String {
        let mut content: String = module_line(MODULE);
        for offset in 0..cases {
            content.push_str(&case_line(offset));
        }
        content.push_str(&seal_line(token, cases));
        content
    }

    #[test]
    fn a_complete_record_parses_as_sealed() {
        assert_eq!(
            parse_progress(&sealed_record(3, 0xDEAD_BEEF_0000_0001)),
            Progress::Sealed {
                module: Some(MODULE.to_owned()),
                token: 0xDEAD_BEEF_0000_0001,
                sealed_cases: 3,
                completed: 3,
            }
        );
    }

    #[test]
    fn a_missing_seal_reports_the_completed_count_and_the_module() {
        let content: String = format!("{}{}{}", module_line(MODULE), case_line(0), case_line(1));
        assert_eq!(
            parse_progress(&content),
            Progress::Unsealed {
                module: Some(MODULE.to_owned()),
                completed: 2,
            }
        );
    }

    #[test]
    fn an_empty_record_reports_zero_completed_cases_and_no_module() {
        assert_eq!(
            parse_progress(""),
            Progress::Unsealed {
                module: None,
                completed: 0,
            }
        );
    }

    #[test]
    fn a_record_without_a_module_line_still_parses_and_names_no_module() {
        let content: String = format!("{}{}", case_line(0), seal_line(7, 1));
        assert_eq!(
            parse_progress(&content),
            Progress::Sealed {
                module: None,
                token: 7,
                sealed_cases: 1,
                completed: 1,
            }
        );
    }

    #[test]
    fn a_torn_trailing_line_is_not_counted() {
        let content: String = format!("{}{}case 1", module_line(MODULE), case_line(0));
        assert_eq!(
            parse_progress(&content),
            Progress::Unsealed {
                module: Some(MODULE.to_owned()),
                completed: 1,
            }
        );
    }

    #[test]
    fn out_of_order_case_indices_are_malformed() {
        let content: String = format!("{}{}", case_line(0), case_line(2));
        assert!(matches!(
            parse_progress(&content),
            Progress::Malformed { .. }
        ));
    }

    #[test]
    fn a_line_after_the_seal_is_malformed() {
        let content: String = format!("{}{}", seal_line(1, 0), case_line(0));
        assert!(matches!(
            parse_progress(&content),
            Progress::Malformed { .. }
        ));
    }

    #[test]
    fn a_malformed_record_carries_the_count_of_well_formed_case_lines() {
        let mut content: String = module_line(MODULE);
        for offset in 0..500usize {
            content.push_str(&case_line(offset));
        }
        content.push_str("not a protocol line\n");
        assert_eq!(
            parse_progress(&content),
            Progress::Malformed {
                detail: "`not a protocol line` is not a module, case or seal line".to_owned(),
                completed: 500,
            }
        );
    }

    #[test]
    fn a_module_line_is_only_valid_as_the_first_line() {
        let trailing: String = format!("{}{}", case_line(0), module_line(MODULE));
        assert!(matches!(
            parse_progress(&trailing),
            Progress::Malformed { completed: 1, .. }
        ));
        let doubled: String = format!("{}{}", module_line(MODULE), module_line(MODULE));
        assert!(matches!(
            parse_progress(&doubled),
            Progress::Malformed { completed: 0, .. }
        ));
    }

    #[test]
    fn unknown_lines_are_malformed() {
        assert!(matches!(
            parse_progress("done\n"),
            Progress::Malformed { .. }
        ));
        assert!(matches!(
            parse_progress("seal zz 1\n"),
            Progress::Malformed { .. }
        ));
        assert!(matches!(
            parse_progress("case one\n"),
            Progress::Malformed { .. }
        ));
        assert!(matches!(
            parse_progress("case 0 extra\n"),
            Progress::Malformed { .. }
        ));
        assert!(matches!(
            parse_progress("module\n"),
            Progress::Malformed { .. }
        ));
        assert!(matches!(
            parse_progress("module a b\n"),
            Progress::Malformed { .. }
        ));
    }

    #[test]
    fn a_corpus_entry_at_the_reader_limit_still_fits_the_wire_after_the_widest_mutation() {
        let widest_growth: usize = MAX_CORPUS_ENTRY_BYTES
            .saturating_mul(2)
            .saturating_add(MAX_CORPUS_ENTRY_BYTES / 4)
            .saturating_add(64);
        assert!(
            widest_growth <= MAX_WIRE_CASE_BYTES,
            "a {MAX_CORPUS_ENTRY_BYTES} byte entry can grow to {widest_growth}, past the {MAX_WIRE_CASE_BYTES} byte wire limit"
        );
    }

    #[test]
    fn the_progress_path_sits_next_to_its_batch() {
        let batch: PathBuf = Path::new("workspace").join("batch-7.bin");
        assert_eq!(
            progress_path(&batch),
            Path::new("workspace").join("batch-7.bin.progress")
        );
    }
}
