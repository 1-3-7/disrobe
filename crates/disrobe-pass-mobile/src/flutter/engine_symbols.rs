use std::collections::BTreeSet;
use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const FLUTTER_ENGINE_SYMBOL_MAP_FORMAT: &str = "disrobe.flutter.engine-symbol-map";
pub const FLUTTER_ENGINE_SYMBOL_MAP_VERSION: u32 = 1;
pub const FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES: usize = 1_048_576;
pub const FLUTTER_ENGINE_SYMBOL_MAP_MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlutterEngineSymbolMapIdentityKind {
    ElfBuildId,
    MachOUuid,
    PePdbGuidAge,
    TextSectionSha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlutterEngineIdentity {
    pub kind: FlutterEngineSymbolMapIdentityKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlutterEngineSymbol {
    pub address: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlutterEngineSymbolMap {
    pub identity: FlutterEngineIdentity,
    pub entries: Vec<FlutterEngineSymbol>,
}

impl FlutterEngineSymbolMap {
    pub fn symbols(&self) -> &[FlutterEngineSymbol] {
        &self.entries
    }

    pub fn validate_image_range(&self, start: u64, size: u64) -> Result<()> {
        let end: u64 = start
            .checked_add(size)
            .ok_or(Error::FlutterEngineSymbolMapImageRangeOverflow { start, size })?;
        for symbol in &self.entries {
            if symbol.address < start || symbol.address >= end {
                return Err(Error::FlutterEngineSymbolMapAddressOutsideImage {
                    address: symbol.address,
                    start,
                    end,
                });
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFlutterEngineSymbolMap {
    format: String,
    version: u32,
    identity: FlutterEngineIdentity,
    symbols: Vec<FlutterEngineSymbol>,
}

pub fn parse_flutter_engine_symbol_map(bytes: &[u8]) -> Result<FlutterEngineSymbolMap> {
    if bytes.len() > FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES {
        return Err(Error::FlutterEngineSymbolMapTooLarge {
            actual: bytes.len(),
            limit: FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES,
        });
    }
    let raw: RawFlutterEngineSymbolMap =
        serde_json::from_slice(bytes).map_err(|error: serde_json::Error| {
            Error::FlutterEngineSymbolMapMalformed(error.to_string())
        })?;
    if raw.format != FLUTTER_ENGINE_SYMBOL_MAP_FORMAT {
        return Err(Error::FlutterEngineSymbolMapMalformed(
            "format must be disrobe.flutter.engine-symbol-map".to_owned(),
        ));
    }
    if raw.version != FLUTTER_ENGINE_SYMBOL_MAP_VERSION {
        return Err(Error::FlutterEngineSymbolMapUnsupportedVersion {
            version: raw.version,
        });
    }
    if raw.identity.value.is_empty() || raw.identity.value.len() > 1024 {
        return Err(Error::FlutterEngineSymbolMapMalformed(
            "identity value must contain 1..=1024 bytes".to_owned(),
        ));
    }
    if raw.symbols.len() > FLUTTER_ENGINE_SYMBOL_MAP_MAX_ENTRIES {
        return Err(Error::FlutterEngineSymbolMapTooManyEntries {
            count: raw.symbols.len(),
            limit: FLUTTER_ENGINE_SYMBOL_MAP_MAX_ENTRIES,
        });
    }
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for symbol in &raw.symbols {
        if symbol.name.is_empty()
            || symbol.name.len() > 4096
            || symbol.name.contains(char::is_control)
        {
            return Err(Error::FlutterEngineSymbolMapMalformed(
                "symbol name must contain 1..=4096 non-control bytes".to_owned(),
            ));
        }
        if !seen.insert(symbol.address) {
            return Err(Error::FlutterEngineSymbolMapDuplicateAddress {
                address: symbol.address,
            });
        }
    }
    let mut entries: Vec<FlutterEngineSymbol> = raw.symbols;
    entries.sort_unstable_by_key(|symbol: &FlutterEngineSymbol| symbol.address);
    Ok(FlutterEngineSymbolMap {
        identity: raw.identity,
        entries,
    })
}

pub fn parse_flutter_engine_symbol_map_reader<R: Read>(
    reader: R,
) -> Result<FlutterEngineSymbolMap> {
    let mut bytes: Vec<u8> = Vec::with_capacity(8192);
    let read_limit: u64 = (FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES as u64) + 1;
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(Error::Io)?;
    parse_flutter_engine_symbol_map(&bytes)
}
