use std::collections::BTreeSet;
use std::io::Read;

use serde::{Deserialize, Serialize};

#[cfg(feature = "native-image")]
use disrobe_binfmt::rewrite::{DerivedKind, ImagePlan, plan_native_image};
#[cfg(feature = "native-image")]
use disrobe_binfmt::{NativeFile, parse_native};

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
    identity: FlutterEngineIdentity,
    entries: Vec<FlutterEngineSymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedFlutterEngineSymbolMap {
    identity: FlutterEngineIdentity,
    entries: Vec<FlutterEngineSymbol>,
}

impl ValidatedFlutterEngineSymbolMap {
    pub const fn identity(&self) -> &FlutterEngineIdentity {
        &self.identity
    }

    pub fn symbols(&self) -> &[FlutterEngineSymbol] {
        &self.entries
    }
}

impl FlutterEngineSymbolMap {
    pub const fn identity(&self) -> &FlutterEngineIdentity {
        &self.identity
    }

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
    let identity: FlutterEngineIdentity = validate_identity(raw.identity)?;
    validate_symbols(&raw.symbols)?;
    let mut entries: Vec<FlutterEngineSymbol> = raw.symbols;
    entries.sort_unstable_by_key(|symbol: &FlutterEngineSymbol| symbol.address);
    Ok(FlutterEngineSymbolMap { identity, entries })
}

fn validate_symbols(symbols: &[FlutterEngineSymbol]) -> Result<()> {
    if symbols.len() > FLUTTER_ENGINE_SYMBOL_MAP_MAX_ENTRIES {
        return Err(Error::FlutterEngineSymbolMapTooManyEntries {
            count: symbols.len(),
            limit: FLUTTER_ENGINE_SYMBOL_MAP_MAX_ENTRIES,
        });
    }
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for symbol in symbols {
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
    Ok(())
}

#[cfg(feature = "native-image")]
pub(crate) fn normalize_flutter_engine_symbol_summary(
    identity: &FlutterEngineIdentity,
    symbols: &[FlutterEngineSymbol],
) -> Result<(FlutterEngineIdentity, Vec<FlutterEngineSymbol>)> {
    let identity: FlutterEngineIdentity = validate_identity(identity.clone())?;
    validate_symbols(symbols)?;
    let mut entries: Vec<FlutterEngineSymbol> = symbols.to_vec();
    entries.sort_unstable_by_key(|symbol: &FlutterEngineSymbol| symbol.address);
    Ok((identity, entries))
}

fn validate_identity(mut identity: FlutterEngineIdentity) -> Result<FlutterEngineIdentity> {
    let value: &str = identity.value.as_str();
    let valid: bool = match identity.kind {
        FlutterEngineSymbolMapIdentityKind::ElfBuildId => {
            matches!(value.len(), 32 | 40) && value.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
        }
        FlutterEngineSymbolMapIdentityKind::MachOUuid => {
            let compact: String = value
                .chars()
                .filter(|character: &char| *character != '-')
                .collect();
            compact.len() == 32
                && compact.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
                && matches!(value.len(), 32 | 36)
        }
        FlutterEngineSymbolMapIdentityKind::PePdbGuidAge => {
            value
                .rsplit_once('-')
                .is_some_and(|(guid, age): (&str, &str)| {
                    guid.len() == 32
                        && guid.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
                        && !age.is_empty()
                        && age.bytes().all(|byte: u8| byte.is_ascii_digit())
                })
        }
        FlutterEngineSymbolMapIdentityKind::TextSectionSha256 => {
            value.len() == 64 && value.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
        }
    };
    if !valid {
        return Err(Error::FlutterEngineSymbolMapMalformed(
            "identity value does not match its declared kind".to_owned(),
        ));
    }
    identity.value.make_ascii_lowercase();
    Ok(identity)
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

#[cfg(feature = "native-image")]
pub fn validate_flutter_engine_symbol_map_for_elf(
    input_bytes: &[u8],
    map: FlutterEngineSymbolMap,
) -> Result<ValidatedFlutterEngineSymbolMap> {
    let FlutterEngineSymbolMap {
        identity,
        mut entries,
    } = map;
    let identity: FlutterEngineIdentity = validate_identity(identity)?;
    validate_symbols(&entries)?;
    entries.sort_unstable_by_key(|symbol: &FlutterEngineSymbol| symbol.address);
    if identity.kind != FlutterEngineSymbolMapIdentityKind::ElfBuildId {
        return Err(Error::FlutterEngineSymbolMapIdentityKind);
    }
    let input_identity: FlutterEngineIdentity = flutter_engine_identity_for_elf(input_bytes)?;
    if identity != input_identity {
        return Err(Error::FlutterEngineSymbolMapIdentityMismatch {
            map: identity.value,
            input: input_identity.value,
        });
    }
    validate_flutter_engine_symbols_for_elf(input_bytes, &entries)?;
    Ok(ValidatedFlutterEngineSymbolMap { identity, entries })
}

#[cfg(feature = "native-image")]
pub fn flutter_engine_identity_for_elf(input_bytes: &[u8]) -> Result<FlutterEngineIdentity> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let plan: ImagePlan = plan_native_image(input_bytes)
        .map_err(|error| Error::FlutterEngineSymbolMapImage(error.to_string()))?;
    let ranges: Vec<(u64, u64)> = plan
        .derived_values()
        .iter()
        .filter(|value| value.kind == DerivedKind::ElfGnuBuildId)
        .map(|value| (value.field_start, value.field_end))
        .collect();
    let [(start, end)] = ranges.as_slice() else {
        if ranges.is_empty() {
            return Err(Error::FlutterEngineSymbolMapIdentityUnavailable);
        }
        return Err(Error::FlutterEngineSymbolMapImage(
            "ELF contains multiple GNU build-ID notes".to_owned(),
        ));
    };
    let start_index: usize = usize::try_from(*start).map_err(|_error| {
        Error::FlutterEngineSymbolMapImage("ELF build-ID start overflows usize".to_owned())
    })?;
    let end_index: usize = usize::try_from(*end).map_err(|_error| {
        Error::FlutterEngineSymbolMapImage("ELF build-ID end overflows usize".to_owned())
    })?;
    let build_id: &[u8] = input_bytes.get(start_index..end_index).ok_or_else(|| {
        Error::FlutterEngineSymbolMapImage("ELF build-ID range exceeds input".to_owned())
    })?;
    if build_id.is_empty() {
        return Err(Error::FlutterEngineSymbolMapImage(
            "ELF build ID is empty".to_owned(),
        ));
    }
    let mut value: String = String::with_capacity(build_id.len() * 2);
    for byte in build_id {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(FlutterEngineIdentity {
        kind: FlutterEngineSymbolMapIdentityKind::ElfBuildId,
        value,
    })
}

#[cfg(feature = "native-image")]
pub fn validate_cached_flutter_engine_symbols_for_elf(
    input_bytes: &[u8],
    identity: FlutterEngineIdentity,
    entries: Vec<FlutterEngineSymbol>,
) -> Result<ValidatedFlutterEngineSymbolMap> {
    let identity: FlutterEngineIdentity = validate_identity(identity)?;
    validate_symbols(&entries)?;
    if identity.kind != FlutterEngineSymbolMapIdentityKind::ElfBuildId {
        return Err(Error::FlutterEngineSymbolMapIdentityKind);
    }
    let input_identity: FlutterEngineIdentity = flutter_engine_identity_for_elf(input_bytes)?;
    if identity != input_identity {
        return Err(Error::FlutterEngineSymbolMapIdentityMismatch {
            map: identity.value,
            input: input_identity.value,
        });
    }
    validate_flutter_engine_symbols_for_elf(input_bytes, &entries)?;
    Ok(ValidatedFlutterEngineSymbolMap { identity, entries })
}

#[cfg(feature = "native-image")]
fn validate_flutter_engine_symbols_for_elf(
    input_bytes: &[u8],
    entries: &[FlutterEngineSymbol],
) -> Result<()> {
    let native: NativeFile = parse_native(input_bytes)
        .map_err(|error| Error::FlutterEngineSymbolMapImage(error.to_string()))?;
    for symbol in entries {
        let inside_segment: bool = native.segments.iter().any(|segment| {
            segment
                .address
                .checked_add(segment.size)
                .is_some_and(|end: u64| symbol.address >= segment.address && symbol.address < end)
        });
        if !inside_segment {
            return Err(Error::FlutterEngineSymbolMapAddressOutsideSegments {
                address: symbol.address,
            });
        }
    }
    Ok(())
}
