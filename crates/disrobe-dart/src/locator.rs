use std::collections::{BTreeMap, BTreeSet};

use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const VM_DATA_SYMBOL: &str = "_kDartVmSnapshotData";
const VM_INSTRUCTIONS_SYMBOL: &str = "_kDartVmSnapshotInstructions";
const ISOLATE_DATA_SYMBOL: &str = "_kDartIsolateSnapshotData";
const ISOLATE_INSTRUCTIONS_SYMBOL: &str = "_kDartIsolateSnapshotInstructions";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartBlobKind {
    VmData,
    VmInstructions,
    IsolateData,
    IsolateInstructions,
}

impl DartBlobKind {
    const fn symbol(self) -> &'static str {
        match self {
            Self::VmData => VM_DATA_SYMBOL,
            Self::VmInstructions => VM_INSTRUCTIONS_SYMBOL,
            Self::IsolateData => ISOLATE_DATA_SYMBOL,
            Self::IsolateInstructions => ISOLATE_INSTRUCTIONS_SYMBOL,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotBlob<'data> {
    pub address: u64,
    pub bytes: &'data [u8],
}

pub fn locate_snapshot_blobs(bytes: &[u8]) -> Result<BTreeMap<DartBlobKind, SnapshotBlob<'_>>> {
    let file: object::File<'_, &[u8]> = object::File::parse(bytes)
        .map_err(|error: object::Error| Error::ObjectParse(error.to_string()))?;
    let mut blobs: BTreeMap<DartBlobKind, SnapshotBlob<'_>> = BTreeMap::new();
    let mut invalid: BTreeSet<DartBlobKind> = BTreeSet::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name): std::result::Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        let kind: Option<DartBlobKind> = match name {
            VM_DATA_SYMBOL => Some(DartBlobKind::VmData),
            VM_INSTRUCTIONS_SYMBOL => Some(DartBlobKind::VmInstructions),
            ISOLATE_DATA_SYMBOL => Some(DartBlobKind::IsolateData),
            ISOLATE_INSTRUCTIONS_SYMBOL => Some(DartBlobKind::IsolateInstructions),
            _ => None,
        };
        let Some(kind): Option<DartBlobKind> = kind else {
            continue;
        };
        let Some(section_index): Option<object::SectionIndex> = symbol.section_index() else {
            invalid.insert(kind);
            continue;
        };
        let Ok(section): std::result::Result<object::Section<'_, '_, &[u8]>, object::Error> =
            file.section_by_index(section_index)
        else {
            invalid.insert(kind);
            continue;
        };
        let Ok(section_bytes): std::result::Result<&[u8], object::Error> = section.data() else {
            invalid.insert(kind);
            continue;
        };
        let Some(relative_u64): Option<u64> = symbol.address().checked_sub(section.address())
        else {
            invalid.insert(kind);
            continue;
        };
        let Ok(relative): std::result::Result<usize, std::num::TryFromIntError> =
            usize::try_from(relative_u64)
        else {
            invalid.insert(kind);
            continue;
        };
        let Ok(size): std::result::Result<usize, std::num::TryFromIntError> =
            usize::try_from(symbol.size())
        else {
            invalid.insert(kind);
            continue;
        };
        if size == 0 {
            invalid.insert(kind);
            continue;
        }
        let Some(end): Option<usize> = relative.checked_add(size) else {
            invalid.insert(kind);
            continue;
        };
        let Some(symbol_bytes): Option<&[u8]> = section_bytes.get(relative..end) else {
            invalid.insert(kind);
            continue;
        };
        let candidate: SnapshotBlob<'_> = SnapshotBlob {
            address: symbol.address(),
            bytes: symbol_bytes,
        };
        if let Some(existing) = blobs.get(&kind) {
            if existing.address != candidate.address || existing.bytes != candidate.bytes {
                return Err(Error::AmbiguousSnapshotSymbol {
                    symbol: kind.symbol(),
                });
            }
        } else {
            blobs.insert(kind, candidate);
        }
    }
    for kind in [
        DartBlobKind::VmData,
        DartBlobKind::VmInstructions,
        DartBlobKind::IsolateData,
        DartBlobKind::IsolateInstructions,
    ] {
        if !blobs.contains_key(&kind) {
            if invalid.contains(&kind) {
                return Err(Error::InvalidSymbolRange {
                    symbol: kind.symbol(),
                });
            }
            return Err(Error::MissingSnapshotSymbol(kind.symbol()));
        }
    }
    Ok(blobs)
}
