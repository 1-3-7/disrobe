use disrobe_bytes::{ByteReadError, ByteReader, LebError, read_uleb128_at};

use crate::error::Result;
use crate::native::NativeFormat;

use super::{ByteCoverage, ClaimSet, RegionClass, coverage_error, read_error, unsupported};

const PREAMBLE_SIZE: u64 = 8;
const MAX_U32_LEB_BYTES: usize = 5;
const WASM_MAGIC: &[u8; 4] = b"\0asm";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Core,
    Component,
}

pub(super) fn map_wasm(bytes: &[u8]) -> Result<ByteCoverage> {
    let encoding: Encoding = read_preamble(bytes)?;
    let mut claims: ClaimSet<'_> = ClaimSet::new(bytes)?;
    claims.claim(0, PREAMBLE_SIZE, RegionClass::Header, "wasm-preamble")?;

    let mut cursor: usize = usize::try_from(PREAMBLE_SIZE)
        .map_err(|_error: std::num::TryFromIntError| coverage_error("preamble size overflows"))?;
    let mut ordinal: usize = 0;
    while cursor < bytes.len() {
        let section_start: usize = cursor;
        let section_id: u8 = *bytes
            .get(cursor)
            .ok_or_else(|| coverage_error("a WebAssembly section id is truncated"))?;
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| coverage_error("a WebAssembly section offset overflows"))?;

        let (payload_size, encoded_size): (u32, usize) = read_section_size(bytes, cursor)?;
        cursor = cursor
            .checked_add(encoded_size)
            .ok_or_else(|| coverage_error("a WebAssembly section header overflows"))?;
        let payload_start: usize = cursor;
        let payload_end: usize = payload_start
            .checked_add(usize::try_from(payload_size).map_err(
                |_error: std::num::TryFromIntError| {
                    coverage_error("a WebAssembly section size overflows usize")
                },
            )?)
            .ok_or_else(|| coverage_error("a WebAssembly section payload overflows"))?;
        if payload_end > bytes.len() {
            return Err(coverage_error(format!(
                "WebAssembly section {ordinal} declares a payload ending at {payload_end}, past the {} byte input",
                bytes.len()
            )));
        }

        let name: String = section_name(encoding, section_id);
        let section_start_u64: u64 =
            u64::try_from(section_start).map_err(|_error: std::num::TryFromIntError| {
                coverage_error("a WebAssembly section offset overflows u64")
            })?;
        let header_size: u64 =
            u64::try_from(payload_start.checked_sub(section_start).ok_or_else(|| {
                coverage_error("a WebAssembly section header ends before it starts")
            })?)
            .map_err(|_error: std::num::TryFromIntError| {
                coverage_error("a WebAssembly section header size overflows u64")
            })?;
        claims.claim(
            section_start_u64,
            header_size,
            RegionClass::Header,
            format!("section[{ordinal}]:{name}-header"),
        )?;
        claims.claim(
            u64::try_from(payload_start).map_err(|_error: std::num::TryFromIntError| {
                coverage_error("a WebAssembly payload offset overflows u64")
            })?,
            u64::from(payload_size),
            section_class(encoding, section_id),
            format!("section[{ordinal}]:{name}-payload"),
        )?;

        cursor = payload_end;
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| coverage_error("the WebAssembly section ordinal overflows"))?;
    }

    claims.finish(NativeFormat::Wasm)
}

fn read_preamble(bytes: &[u8]) -> Result<Encoding> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let magic: &[u8] = reader
        .read_bytes(WASM_MAGIC.len())
        .map_err(|error: ByteReadError| read_error("the WebAssembly magic", error))?;
    if magic != WASM_MAGIC {
        return Err(coverage_error("the WebAssembly magic is invalid"));
    }
    let version: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| read_error("the WebAssembly version", error))?;
    let layer: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| read_error("the WebAssembly layer", error))?;

    match (version, layer) {
        (1, 0) => Ok(Encoding::Core),
        (13, 1) => Ok(Encoding::Component),
        _ => Err(unsupported(
            NativeFormat::Wasm,
            format!("version {version} and layer {layer} do not have a supported section framing"),
        )),
    }
}

fn read_section_size(bytes: &[u8], offset: usize) -> Result<(u32, usize)> {
    let encoded: &[u8] = bytes
        .get(offset..)
        .ok_or_else(|| coverage_error("a WebAssembly section length is truncated"))?;
    let inspected: usize = encoded.len().min(MAX_U32_LEB_BYTES);
    let terminator: Option<usize> = encoded
        .get(..inspected)
        .and_then(|window: &[u8]| window.iter().position(|byte: &u8| byte & 0x80 == 0));
    let Some(last_index): Option<usize> = terminator else {
        let detail: &str = if encoded.len() < MAX_U32_LEB_BYTES {
            "is truncated"
        } else {
            "uses more than five bytes"
        };
        return Err(coverage_error(format!(
            "the WebAssembly section length at {offset} {detail}"
        )));
    };

    let expected_size: usize = last_index
        .checked_add(1)
        .ok_or_else(|| coverage_error("a WebAssembly section length width overflows"))?;
    let (value, consumed): (u64, usize) =
        read_uleb128_at(bytes, offset).map_err(|error: LebError| match error {
            LebError::OutOfBounds(inner) => read_error("a WebAssembly section length", inner),
            LebError::Overflow { .. } => coverage_error(format!(
                "the WebAssembly section length at {offset} overflows unsigned LEB128"
            )),
        })?;
    if consumed != expected_size || consumed > MAX_U32_LEB_BYTES {
        return Err(coverage_error(format!(
            "the WebAssembly section length at {offset} uses more than five bytes"
        )));
    }
    let value: u32 = u32::try_from(value).map_err(|_error: std::num::TryFromIntError| {
        coverage_error(format!(
            "the WebAssembly section length at {offset} exceeds u32"
        ))
    })?;

    Ok((value, consumed))
}

fn section_name(encoding: Encoding, id: u8) -> String {
    let known: Option<&'static str> = match encoding {
        Encoding::Core => match id {
            0 => Some("custom"),
            1 => Some("type"),
            2 => Some("import"),
            3 => Some("function"),
            4 => Some("table"),
            5 => Some("memory"),
            6 => Some("global"),
            7 => Some("export"),
            8 => Some("start"),
            9 => Some("element"),
            10 => Some("code"),
            11 => Some("data"),
            12 => Some("data-count"),
            13 => Some("tag"),
            _ => None,
        },
        Encoding::Component => match id {
            0 => Some("custom"),
            1 => Some("core-module"),
            2 => Some("core-instance"),
            3 => Some("core-type"),
            4 => Some("component"),
            5 => Some("instance"),
            6 => Some("alias"),
            7 => Some("type"),
            8 => Some("canonical"),
            9 => Some("start"),
            10 => Some("import"),
            11 => Some("export"),
            _ => None,
        },
    };
    known.map_or_else(|| format!("unknown-{id}"), str::to_owned)
}

const fn section_class(encoding: Encoding, id: u8) -> RegionClass {
    match (encoding, id) {
        (Encoding::Core, 10) | (Encoding::Component, 1 | 4) => RegionClass::Code,
        (Encoding::Core, 1..=9 | 12 | 13) | (Encoding::Component, 2..=3 | 5..=11) => {
            RegionClass::Table
        }
        _ => RegionClass::Data,
    }
}
