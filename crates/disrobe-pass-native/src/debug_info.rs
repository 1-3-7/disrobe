use std::collections::BTreeMap;
use std::io::Cursor;

use pdb::FallibleIterator as _;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DwarfVersion {
    V2,
    V3,
    V4,
    V5,
    Unknown,
}

impl DwarfVersion {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            2 => Self::V2,
            3 => Self::V3,
            4 => Self::V4,
            5 => Self::V5,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DwarfSummary {
    pub version: DwarfVersion,
    pub compilation_units: u32,
    pub line_program_rows: u32,
    pub file_table_entries: u32,
}

pub fn summarize_dwarf<R>(dwarf: &gimli::Dwarf<R>) -> Result<DwarfSummary>
where
    R: gimli::Reader,
{
    let mut cu_count: u32 = 0;
    let mut line_rows: u32 = 0;
    let mut file_count: u32 = 0;
    let mut detected_version: DwarfVersion = DwarfVersion::Unknown;
    let mut iter: gimli::DebugInfoUnitHeadersIter<R> = dwarf.units();
    while let Some(header) = iter
        .next()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        cu_count = cu_count.saturating_add(1);
        let unit: gimli::Unit<R> = dwarf
            .unit(header)
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;
        let version_u16: u16 = unit.header.version();
        detected_version = DwarfVersion::from_u16(version_u16);
        if let Some(lp) = unit.line_program.clone() {
            let header_files: usize = lp.header().file_names().len();
            file_count = file_count.saturating_add(header_files as u32);
            let mut rows: gimli::LineRows<R, gimli::IncompleteLineProgram<R>> = lp.rows();
            while rows
                .next_row()
                .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
                .is_some()
            {
                line_rows = line_rows.saturating_add(1);
            }
        }
    }
    Ok(DwarfSummary {
        version: detected_version,
        compilation_units: cu_count,
        line_program_rows: line_rows,
        file_table_entries: file_count,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbSummary {
    pub machine: Option<String>,
    pub module_count: u32,
    pub symbol_count: u32,
    pub age: u32,
    pub guid: String,
}

pub fn summarize_pdb(bytes: &[u8]) -> Result<PdbSummary> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut pdb: pdb::PDB<'_, Cursor<&[u8]>> =
        pdb::PDB::open(cursor).map_err(|e: pdb::Error| Error::Pdb(e.to_string()))?;
    let info: pdb::PDBInformation<'_> = pdb
        .pdb_information()
        .map_err(|e: pdb::Error| Error::Pdb(e.to_string()))?;
    let dbi: pdb::DebugInformation<'_> = pdb
        .debug_information()
        .map_err(|e: pdb::Error| Error::Pdb(e.to_string()))?;
    let machine: Option<String> = dbi
        .machine_type()
        .ok()
        .map(|m: pdb::MachineType| format!("{m:?}"));
    let mut module_count: u32 = 0;
    let mut modules: pdb::ModuleIter<'_> = dbi.modules().map_err(|e| Error::Pdb(e.to_string()))?;
    while modules
        .next()
        .map_err(|e: pdb::Error| Error::Pdb(e.to_string()))?
        .is_some()
    {
        module_count = module_count.saturating_add(1);
    }
    let symbol_table: pdb::SymbolTable<'_> = pdb
        .global_symbols()
        .map_err(|e: pdb::Error| Error::Pdb(e.to_string()))?;
    let mut symbol_count: u32 = 0;
    let mut sym_iter: pdb::SymbolIter<'_> = symbol_table.iter();
    while sym_iter
        .next()
        .map_err(|e: pdb::Error| Error::Pdb(e.to_string()))?
        .is_some()
    {
        symbol_count = symbol_count.saturating_add(1);
    }
    Ok(PdbSummary {
        machine,
        module_count,
        symbol_count,
        age: info.age,
        guid: format!("{:?}", info.guid),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabsEntry {
    pub name: String,
    pub kind: u8,
    pub other: u8,
    pub desc: u16,
    pub value: u32,
}

pub fn parse_stabs(bytes: &[u8], string_table: &[u8]) -> Result<Vec<StabsEntry>> {
    const STRX_OFF: usize = 0;
    const KIND_OFF: usize = 4;
    const OTHER_OFF: usize = 5;
    const DESC_OFF: usize = 6;
    const VALUE_OFF: usize = 8;
    const ENTRY_SIZE: usize = 12;
    if bytes.len() % ENTRY_SIZE != 0 {
        return Err(Error::Stabs(bytes.len()));
    }
    let mut entries: Vec<StabsEntry> = Vec::with_capacity(bytes.len() / ENTRY_SIZE);
    let mut off: usize = 0;
    while off + ENTRY_SIZE <= bytes.len() {
        let strx: usize = u32::from_le_bytes([
            bytes[off + STRX_OFF],
            bytes[off + STRX_OFF + 1],
            bytes[off + STRX_OFF + 2],
            bytes[off + STRX_OFF + 3],
        ]) as usize;
        let kind: u8 = bytes[off + KIND_OFF];
        let other: u8 = bytes[off + OTHER_OFF];
        let desc: u16 = u16::from_le_bytes([bytes[off + DESC_OFF], bytes[off + DESC_OFF + 1]]);
        let value: u32 = u32::from_le_bytes([
            bytes[off + VALUE_OFF],
            bytes[off + VALUE_OFF + 1],
            bytes[off + VALUE_OFF + 2],
            bytes[off + VALUE_OFF + 3],
        ]);
        let name: String =
            read_cstring_at(string_table, strx).ok_or(Error::Stabs(off + STRX_OFF))?;
        entries.push(StabsEntry {
            name,
            kind,
            other,
            desc,
            value,
        });
        off += ENTRY_SIZE;
    }
    Ok(entries)
}

fn read_cstring_at(string_table: &[u8], offset: usize) -> Option<String> {
    if offset >= string_table.len() {
        return None;
    }
    let slice: &[u8] = &string_table[offset..];
    let end: usize = slice
        .iter()
        .position(|b: &u8| *b == 0)
        .unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

#[must_use]
pub fn classify_dwarf_versions(versions: &[u16]) -> BTreeMap<DwarfVersion, u32> {
    let mut acc: BTreeMap<DwarfVersion, u32> = BTreeMap::new();
    for v in versions {
        *acc.entry(DwarfVersion::from_u16(*v)).or_insert(0) += 1;
    }
    acc
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn dwarf_version_roundtrip() {
        for v in 2u16..=5 {
            assert_ne!(DwarfVersion::from_u16(v), DwarfVersion::Unknown);
        }
        assert_eq!(DwarfVersion::from_u16(99), DwarfVersion::Unknown);
    }

    #[test]
    fn pdb_summary_rejects_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 4096];
        let err: Error = summarize_pdb(&bytes).expect_err("must fail on non-pdb");
        assert!(matches!(err, Error::Pdb(_)));
    }

    #[test]
    fn stabs_parser_empty_input_is_ok() {
        let out: Vec<StabsEntry> = parse_stabs(&[], &[]).expect("empty stabs");
        assert!(out.is_empty());
    }

    #[test]
    fn stabs_parser_single_entry_roundtrip() {
        let strtab: &[u8] = b"\0hello\0";
        let mut entry: Vec<u8> = Vec::new();
        entry.extend_from_slice(&1u32.to_le_bytes());
        entry.push(0x24);
        entry.push(0);
        entry.extend_from_slice(&7u16.to_le_bytes());
        entry.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let out: Vec<StabsEntry> = parse_stabs(&entry, strtab).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "hello");
        assert_eq!(out[0].kind, 0x24);
        assert_eq!(out[0].value, 0xDEAD_BEEF);
    }

    #[test]
    fn stabs_parser_rejects_truncated_entry() {
        let buf: [u8; 7] = [0u8; 7];
        let err: Error = parse_stabs(&buf, &[]).expect_err("truncated");
        assert!(matches!(err, Error::Stabs(_)));
    }

    #[test]
    fn dwarf_version_histogram() {
        let hist: BTreeMap<DwarfVersion, u32> = classify_dwarf_versions(&[2, 4, 4, 5, 5, 5, 6]);
        assert_eq!(hist[&DwarfVersion::V5], 3);
        assert_eq!(hist[&DwarfVersion::Unknown], 1);
    }
}
