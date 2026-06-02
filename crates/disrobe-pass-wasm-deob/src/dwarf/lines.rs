use std::collections::BTreeMap;

use gimli::{Dwarf, FileEntry, IncompleteLineProgram, LineProgramHeader, Reader, Unit};
use serde::Serialize;

use crate::dwarf::unit::Slice;
use crate::error::{Error, Result};

pub type Pc = u64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct LineMap {
    pub entries: BTreeMap<Pc, SourceLocation>,
}

impl LineMap {
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    #[must_use]
    pub fn resolve(&self, pc: Pc) -> Option<&SourceLocation> {
        self.entries
            .range(..=pc)
            .next_back()
            .map(|(_, loc): (&Pc, &SourceLocation)| loc)
    }
}

pub fn build(dwarf: &Dwarf<Slice<'_>>, unit: &Unit<Slice<'_>>) -> Result<LineMap> {
    let Some(program): Option<IncompleteLineProgram<Slice<'_>, usize>> = unit.line_program.clone()
    else {
        return Ok(LineMap::default());
    };
    let header_snapshot: LineProgramHeader<Slice<'_>, usize> = program.header().clone();
    let comp_dir: Option<String> = match unit.comp_dir.as_ref() {
        Some(r) => Some(
            Reader::to_string_lossy(r)
                .map_err(map_gimli_err)?
                .into_owned(),
        ),
        None => None,
    };

    let mut rows_iter = program.rows();
    let mut entries: BTreeMap<Pc, SourceLocation> = BTreeMap::new();
    while let Some((header, row)) = rows_iter.next_row().map_err(map_gimli_err)? {
        if row.end_sequence() {
            continue;
        }
        let address: u64 = row.address();
        let file_entry: Option<&FileEntry<Slice<'_>, usize>> = row.file(header);
        let file_name: String = match file_entry {
            Some(entry) => format_file(dwarf, unit, &header_snapshot, entry, comp_dir.as_deref())?,
            None => "<unknown>".to_string(),
        };
        let line: u32 = row
            .line()
            .map_or(0, |nz| u32::try_from(nz.get()).unwrap_or(u32::MAX));
        let column: u32 = match row.column() {
            gimli::ColumnType::LeftEdge => 0,
            gimli::ColumnType::Column(c) => u32::try_from(c.get()).unwrap_or(u32::MAX),
        };
        entries.insert(
            address,
            SourceLocation {
                file: file_name,
                line,
                column,
            },
        );
    }
    Ok(LineMap { entries })
}

fn format_file(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    header: &LineProgramHeader<Slice<'_>, usize>,
    file: &FileEntry<Slice<'_>, usize>,
    comp_dir: Option<&str>,
) -> Result<String> {
    let name_reader: Slice<'_> = dwarf
        .attr_string(unit, file.path_name())
        .map_err(map_gimli_err)?;
    let name: String = Reader::to_string_lossy(&name_reader)
        .map_err(map_gimli_err)?
        .into_owned();

    let dir_value: Option<String> = match file.directory(header) {
        Some(dir_attr) => {
            let dir_reader: Slice<'_> = dwarf.attr_string(unit, dir_attr).map_err(map_gimli_err)?;
            Some(
                Reader::to_string_lossy(&dir_reader)
                    .map_err(map_gimli_err)?
                    .into_owned(),
            )
        }
        None => None,
    };

    let combined: String = match (dir_value.as_deref(), comp_dir) {
        (Some(dir), _) if is_absolute(dir) => join_path(dir, &name),
        (Some(dir), Some(base)) => join_path(&join_path(base, dir), &name),
        (Some(dir), None) => join_path(dir, &name),
        (None, Some(base)) => join_path(base, &name),
        (None, None) => name,
    };
    Ok(normalize_separators(&combined))
}

#[inline]
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || (path.len() >= 2 && path.as_bytes()[1] == b':')
}

#[inline]
fn join_path(a: &str, b: &str) -> String {
    if a.is_empty() {
        return b.to_string();
    }
    if b.is_empty() {
        return a.to_string();
    }
    let needs_sep: bool = !a.ends_with('/') && !a.ends_with('\\');
    if needs_sep {
        format!("{a}/{b}")
    } else {
        format!("{a}{b}")
    }
}

#[inline]
fn normalize_separators(path: &str) -> String {
    path.replace('\\', "/")
}

#[inline]
fn map_gimli_err(err: gimli::Error) -> Error {
    Error::Parse(format!("line program: {err}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_line_map_resolve_returns_none() {
        let map: LineMap = LineMap::default();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(map.resolve(0x42).is_none());
    }

    #[test]
    fn resolve_returns_floor_entry() {
        let mut map: LineMap = LineMap::default();
        map.entries.insert(
            0x10,
            SourceLocation {
                file: "a.c".into(),
                line: 1,
                column: 1,
            },
        );
        map.entries.insert(
            0x20,
            SourceLocation {
                file: "a.c".into(),
                line: 2,
                column: 1,
            },
        );
        let found: &SourceLocation = map.resolve(0x1F).unwrap();
        assert_eq!(found.line, 1);
        let found2: &SourceLocation = map.resolve(0x20).unwrap();
        assert_eq!(found2.line, 2);
        let found3: &SourceLocation = map.resolve(0x99).unwrap();
        assert_eq!(found3.line, 2);
    }

    #[test]
    fn path_join_handles_separators() {
        assert_eq!(join_path("/home/user", "main.c"), "/home/user/main.c");
        assert_eq!(join_path("/home/user/", "main.c"), "/home/user/main.c");
        assert_eq!(join_path("", "main.c"), "main.c");
        assert_eq!(join_path("dir", ""), "dir");
    }

    #[test]
    fn normalize_replaces_backslashes() {
        assert_eq!(normalize_separators(r"C:\src\main.c"), "C:/src/main.c");
    }

    #[test]
    fn absolute_path_detection() {
        assert!(is_absolute("/a"));
        assert!(is_absolute(r"\a"));
        assert!(is_absolute(r"C:\x"));
        assert!(!is_absolute("a/b"));
        assert!(!is_absolute("rel/path"));
    }
}
