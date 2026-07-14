use std::collections::BTreeMap;

use disrobe_binfmt::{QuotaGuard, sanitize_entry_path};
use disrobe_bytes::{ByteReader, align_up_u32};
use serde::Deserialize;

use crate::CarveConfig;
use crate::detect::find_from;
use crate::error::{Error, Result};
use crate::model::{CarveReport, Compression, RecoveredAsset, WebviewFamily};

const ANCHOR: &[u8] = b"{\"files\":";
const PREFIX_LEN: usize = 16;
const SIZE_PICKLE_PAYLOAD: u32 = 4;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AsarHeader {
    json_start: usize,
    json_end: usize,
    data_base: usize,
}

#[derive(Debug, Deserialize)]
struct RawNode {
    #[serde(default)]
    files: Option<BTreeMap<String, Self>>,
    #[serde(default)]
    offset: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    unpacked: Option<bool>,
}

pub(crate) fn locate_header(bytes: &[u8], max_candidates: usize) -> Option<AsarHeader> {
    let mut search: usize = 0;
    let mut seen: usize = 0;
    while let Some(anchor_pos) = find_from(bytes, ANCHOR, search) {
        search = anchor_pos + 1;
        seen += 1;
        if seen > max_candidates {
            break;
        }
        if anchor_pos < PREFIX_LEN {
            continue;
        }
        let base: usize = anchor_pos - PREFIX_LEN;
        if let Some(header) = validate_header(bytes, base) {
            return Some(header);
        }
    }
    None
}

fn validate_header(bytes: &[u8], base: usize) -> Option<AsarHeader> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(base).ok()?;
    let size_field: u32 = reader.read_u32_le().ok()?;
    if size_field != SIZE_PICKLE_PAYLOAD {
        return None;
    }
    let header_buf_len: u32 = reader.read_u32_le().ok()?;
    let payload_size: u32 = reader.read_u32_le().ok()?;
    let json_len: u32 = reader.read_u32_le().ok()?;
    if header_buf_len != payload_size.checked_add(4)? {
        return None;
    }
    if payload_size != align_up_u32(json_len, 4).checked_add(4)? {
        return None;
    }
    let json_start: usize = base.checked_add(PREFIX_LEN)?;
    let json_end: usize = json_start.checked_add(json_len as usize)?;
    if json_end > bytes.len() {
        return None;
    }
    let data_base: usize = base.checked_add(8)?.checked_add(header_buf_len as usize)?;
    if data_base > bytes.len() {
        return None;
    }
    Some(AsarHeader {
        json_start,
        json_end,
        data_base,
    })
}

pub(crate) fn extract(bytes: &[u8], cfg: &CarveConfig) -> Result<CarveReport> {
    let header: AsarHeader = locate_header(bytes, cfg.max_scan_candidates)
        .ok_or_else(|| Error::AsarHeader("no valid asar pickle header located".to_owned()))?;
    let json: &[u8] = bytes
        .get(header.json_start..header.json_end)
        .ok_or_else(|| Error::AsarHeader("json slice out of range".to_owned()))?;
    let root: RawNode = serde_json::from_slice(json)?;
    let mut walk: Walk<'_> = Walk {
        bytes,
        data_base: header.data_base,
        max_depth: cfg.max_depth,
        guard: QuotaGuard::new(cfg.quota),
        assets: Vec::new(),
        external: Vec::new(),
    };
    let mut path_stack: Vec<String> = Vec::new();
    walk.descend(&root, &mut path_stack, 0)?;
    Ok(CarveReport {
        family: WebviewFamily::Electron,
        assets: walk.assets,
        external_unpacked: walk.external,
    })
}

struct Walk<'a> {
    bytes: &'a [u8],
    data_base: usize,
    max_depth: usize,
    guard: QuotaGuard,
    assets: Vec<RecoveredAsset>,
    external: Vec<String>,
}

impl Walk<'_> {
    fn descend(
        &mut self,
        node: &RawNode,
        path_stack: &mut Vec<String>,
        depth: usize,
    ) -> Result<()> {
        if depth > self.max_depth {
            return Err(Error::DepthExceeded(self.max_depth));
        }
        if let Some(children) = node.files.as_ref() {
            for (name, child) in children {
                path_stack.push(name.clone());
                self.descend(child, path_stack, depth + 1)?;
                path_stack.pop();
            }
            return Ok(());
        }
        let Some(offset_str) = node.offset.as_deref() else {
            return Ok(());
        };
        let joined: String = path_stack.join("/");
        let Ok(safe) = sanitize_entry_path(&joined) else {
            return Ok(());
        };
        if node.unpacked.unwrap_or(false) {
            self.external.push(safe);
            return Ok(());
        }
        let size: u64 = node.size.unwrap_or(0);
        let slice: &[u8] = read_entry(self.bytes, self.data_base, &safe, offset_str, size)?;
        self.guard
            .admit_entry(&safe, slice.len() as u64, slice.len() as u64)?;
        self.assets.push(RecoveredAsset {
            path: safe,
            bytes: slice.to_vec(),
            compression: Compression::None,
        });
        Ok(())
    }
}

fn read_entry<'a>(
    bytes: &'a [u8],
    data_base: usize,
    path: &str,
    offset_str: &str,
    size: u64,
) -> Result<&'a [u8]> {
    let offset: u64 = offset_str.parse::<u64>().map_err(|_| Error::AsarBounds {
        path: path.to_owned(),
        detail: format!("offset `{offset_str}` is not a decimal integer"),
    })?;
    let offset: usize = usize::try_from(offset).map_err(|_| Error::AsarBounds {
        path: path.to_owned(),
        detail: "offset exceeds addressable range".to_owned(),
    })?;
    let size: usize = usize::try_from(size).map_err(|_| Error::AsarBounds {
        path: path.to_owned(),
        detail: "size exceeds addressable range".to_owned(),
    })?;
    let absolute: usize = data_base
        .checked_add(offset)
        .ok_or_else(|| Error::AsarBounds {
            path: path.to_owned(),
            detail: "data base plus offset overflows".to_owned(),
        })?;
    let end: usize = absolute
        .checked_add(size)
        .ok_or_else(|| Error::AsarBounds {
            path: path.to_owned(),
            detail: "entry end overflows".to_owned(),
        })?;
    bytes.get(absolute..end).ok_or_else(|| Error::AsarBounds {
        path: path.to_owned(),
        detail: format!(
            "range [{absolute}..{end}] exceeds buffer length {}",
            bytes.len()
        ),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn pickle(json: &[u8], data: &[u8]) -> Vec<u8> {
        let json_len: u32 = u32::try_from(json.len()).expect("json len fits");
        let aligned: u32 = align_up_u32(json_len, 4);
        let payload_size: u32 = aligned + 4;
        let header_buf_len: u32 = payload_size + 4;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&SIZE_PICKLE_PAYLOAD.to_le_bytes());
        out.extend_from_slice(&header_buf_len.to_le_bytes());
        out.extend_from_slice(&payload_size.to_le_bytes());
        out.extend_from_slice(&json_len.to_le_bytes());
        out.extend_from_slice(json);
        out.extend(std::iter::repeat_n(0u8, (aligned - json_len) as usize));
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn validates_genuine_header() {
        let json: &[u8] = br#"{"files":{"a.txt":{"size":3,"offset":"0"}}}"#;
        let bytes: Vec<u8> = pickle(json, b"abc");
        let header: AsarHeader = locate_header(&bytes, 8).expect("header located");
        assert_eq!(header.data_base, bytes.len() - 3);
    }

    #[test]
    fn rejects_truncated_prefix() {
        assert!(locate_header(&[0x7b, 0x22, 0x66], 8).is_none());
        assert!(locate_header(b"{\"files\":", 8).is_none());
    }

    #[test]
    fn out_of_bounds_offset_errors_without_panic() {
        let json: &[u8] = br#"{"files":{"a.txt":{"size":9999,"offset":"0"}}}"#;
        let bytes: Vec<u8> = pickle(json, b"abc");
        let cfg: CarveConfig = CarveConfig::default();
        let err: Error = extract(&bytes, &cfg).expect_err("must reject oob");
        assert!(matches!(err, Error::AsarBounds { .. }));
    }
}
