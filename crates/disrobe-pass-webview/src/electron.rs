use std::collections::{BTreeMap, BTreeSet};

use disrobe_binfmt::{QuotaGuard, sanitize_entry_path};
use disrobe_bytes::{ByteReader, align_up_u32};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::CarveConfig;
use crate::detect::find_from;
use crate::embedded::case_collision_key;
use crate::error::{Error, Result};
use crate::model::{
    CarveReport, Compression, EntryRefusal, IntegrityStatus, RecoveredAsset, SymlinkEntry,
    WebviewFamily,
};

const ANCHOR: &[u8] = b"{\"files\":";
const PREFIX_LEN: usize = 16;
const SIZE_PICKLE_PAYLOAD: u32 = 4;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const MAX_ENTRY_PATH_BYTES: usize = 4096;

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
    #[serde(default)]
    executable: Option<bool>,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    integrity: Option<Integrity>,
}

#[derive(Debug, Deserialize)]
struct Integrity {
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    hash: Option<String>,
    #[serde(rename = "blockSize", default)]
    block_size: Option<u64>,
    #[serde(default)]
    blocks: Vec<String>,
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
    let mut leaves: Vec<Leaf<'_>> = Vec::new();
    let mut path_stack: Vec<&str> = Vec::new();
    collect_leaves(&root, &mut path_stack, 0, cfg, &mut leaves)?;
    let declared: usize = leaves.len();
    let colliding: BTreeSet<String> = colliding_keys(&leaves);
    let mut walk: Walk<'_> = Walk {
        bytes,
        data_base: header.data_base,
        data_len: bytes.len().saturating_sub(header.data_base) as u64,
        max_aggregate_ratio: cfg.quota.max_aggregate_ratio,
        emitted: 0,
        guard: QuotaGuard::new(cfg.quota),
        assets: Vec::new(),
        external: Vec::new(),
        symlinks: Vec::new(),
        refusals: Vec::new(),
    };
    for leaf in leaves {
        walk.admit(leaf, &colliding);
    }
    let recovered: usize = walk.assets.len() + walk.external.len() + walk.symlinks.len();
    Ok(CarveReport {
        family: WebviewFamily::Electron,
        assets: walk.assets,
        external_unpacked: walk.external,
        symlinks: walk.symlinks,
        directories: Vec::new(),
        declared,
        recovered,
        refusals: walk.refusals,
    })
}

struct Leaf<'n> {
    path: String,
    safe: Option<String>,
    node: &'n RawNode,
}

fn collect_leaves<'n>(
    node: &'n RawNode,
    path_stack: &mut Vec<&'n str>,
    depth: usize,
    cfg: &CarveConfig,
    leaves: &mut Vec<Leaf<'n>>,
) -> Result<()> {
    if depth > cfg.max_depth {
        return Err(Error::DepthExceeded(cfg.max_depth));
    }
    if let Some(children) = node.files.as_ref() {
        for (name, child) in children {
            path_stack.push(name);
            collect_leaves(child, path_stack, depth + 1, cfg, leaves)?;
            path_stack.pop();
        }
        return Ok(());
    }
    let (path, overlong): (String, bool) = bounded_join(path_stack);
    if leaves.len() >= cfg.quota.max_entries {
        return Err(Error::Quota {
            entry: path,
            reason: format!(
                "the table declares more than {} entries",
                cfg.quota.max_entries
            ),
        });
    }
    let safe: Option<String> = if overlong {
        None
    } else {
        sanitize_entry_path(&path).ok()
    };
    leaves.push(Leaf { path, safe, node });
    Ok(())
}

fn bounded_join(components: &[&str]) -> (String, bool) {
    let mut out: String = String::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        let room: usize = MAX_ENTRY_PATH_BYTES.saturating_sub(out.len());
        if component.len() > room {
            let mut cut: usize = room;
            while !component.is_char_boundary(cut) {
                cut -= 1;
            }
            out.push_str(&component[..cut]);
            return (out, true);
        }
        out.push_str(component);
    }
    (out, false)
}

fn colliding_keys(leaves: &[Leaf<'_>]) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for safe in leaves
        .iter()
        .filter_map(|leaf: &Leaf<'_>| leaf.safe.as_deref())
    {
        *counts.entry(case_collision_key(safe)).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .filter(|(_, count): &(String, usize)| *count > 1)
        .map(|(key, _): (String, usize)| key)
        .collect()
}

struct Walk<'a> {
    bytes: &'a [u8],
    data_base: usize,
    data_len: u64,
    max_aggregate_ratio: u64,
    emitted: u64,
    guard: QuotaGuard,
    assets: Vec<RecoveredAsset>,
    external: Vec<String>,
    symlinks: Vec<SymlinkEntry>,
    refusals: Vec<EntryRefusal>,
}

impl Walk<'_> {
    fn refuse(&mut self, path: String, reason: String) {
        self.refusals.push(EntryRefusal { path, reason });
    }

    fn admit(&mut self, leaf: Leaf<'_>, colliding: &BTreeSet<String>) {
        let node: &RawNode = leaf.node;
        let Some(safe) = leaf.safe else {
            self.refuse(
                leaf.path,
                "the entry name is not a safe relative path".to_owned(),
            );
            return;
        };
        if colliding.contains(&case_collision_key(&safe)) {
            self.refuse(
                safe,
                "another entry names the same path when case is ignored".to_owned(),
            );
            return;
        }
        if let Some(target) = node.link.as_deref() {
            if resolve_symlink_target(&safe, target).is_some() {
                self.symlinks.push(SymlinkEntry {
                    path: safe,
                    target: target.to_owned(),
                });
            } else {
                self.refuse(safe, "the link target escapes the archive".to_owned());
            }
            return;
        }
        if node.unpacked.unwrap_or(false) {
            self.external.push(safe);
            return;
        }
        let Some(offset_str) = node.offset.as_deref() else {
            self.refuse(safe, "the entry has no data offset".to_owned());
            return;
        };
        let size: u64 = node.size.unwrap_or(0);
        let slice: &[u8] = match read_entry(self.bytes, self.data_base, &safe, offset_str, size) {
            Ok(slice) => slice,
            Err(error) => {
                self.refuse(safe, error.to_string());
                return;
            }
        };
        let len: u64 = slice.len() as u64;
        let emitted: u64 = self.emitted.saturating_add(len);
        if emitted > self.data_len.saturating_mul(self.max_aggregate_ratio) {
            self.refuse(
                safe,
                format!(
                    "its {len} bytes would lift the recovered total to {emitted}, over {} times the {}-byte data region",
                    self.max_aggregate_ratio, self.data_len
                ),
            );
            return;
        }
        if let Err(error) = self.guard.admit_entry(&safe, len, len) {
            self.refuse(safe, error.to_string());
            return;
        }
        self.emitted = emitted;
        let integrity: IntegrityStatus = verify_integrity(slice, node.integrity.as_ref());
        self.assets.push(RecoveredAsset {
            path: safe,
            bytes: slice.to_vec(),
            compression: Compression::None,
            executable: node.executable.unwrap_or(false),
            integrity,
        });
    }
}

pub(crate) fn resolve_symlink_target(link_path: &str, target: &str) -> Option<String> {
    let normalized: String = target.replace('\\', "/");
    if normalized.is_empty() || normalized.starts_with('/') {
        return None;
    }
    if normalized
        .split('/')
        .any(|component: &str| component.contains(':'))
    {
        return None;
    }
    let mut stack: Vec<&str> = link_path.split('/').collect();
    stack.pop();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                stack.pop()?;
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        return None;
    }
    Some(stack.join("/"))
}

fn verify_integrity(data: &[u8], integrity: Option<&Integrity>) -> IntegrityStatus {
    let Some(integrity) = integrity else {
        return IntegrityStatus::Absent;
    };
    let Some(expected) = integrity.hash.as_deref() else {
        return IntegrityStatus::Absent;
    };
    let algorithm_ok: bool = integrity
        .algorithm
        .as_deref()
        .is_none_or(|value: &str| value.eq_ignore_ascii_case("SHA256"));
    if !algorithm_ok {
        return IntegrityStatus::Absent;
    }
    if !sha256_hex(data).eq_ignore_ascii_case(expected) {
        return IntegrityStatus::Mismatch;
    }
    if let Some(block_size) = integrity.block_size
        && let Ok(block_size) = usize::try_from(block_size)
        && block_size > 0
        && !blocks_match(data, block_size, &integrity.blocks)
    {
        return IntegrityStatus::Mismatch;
    }
    IntegrityStatus::Verified
}

fn blocks_match(data: &[u8], block_size: usize, blocks: &[String]) -> bool {
    for (index, chunk) in data.chunks(block_size).enumerate() {
        let Some(expected) = blocks.get(index) else {
            break;
        };
        if !sha256_hex(chunk).eq_ignore_ascii_case(expected) {
            return false;
        }
    }
    true
}

fn sha256_hex(data: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(data).into();
    let mut out: String = String::with_capacity(digest.len() * 2);
    for &byte in &digest {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
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
    fn symlink_targets_that_leave_the_tree_are_refused() {
        assert_eq!(
            resolve_symlink_target("node_modules/a/index.js", "../b/index.js").as_deref(),
            Some("node_modules/b/index.js")
        );
        assert_eq!(
            resolve_symlink_target("a/b/c.js", "./d.js").as_deref(),
            Some("a/b/d.js")
        );
        for (link, target) in [
            ("a/b.js", "../../etc/passwd"),
            ("a/b.js", "/etc/passwd"),
            ("a/b.js", "C:/Windows/win.ini"),
            ("a/b.js", "..\\..\\windows\\system32"),
            ("a/b.js", ".."),
            ("a/b.js", ""),
        ] {
            assert!(
                resolve_symlink_target(link, target).is_none(),
                "symlink {link} -> {target} escapes the extraction root and must be refused"
            );
        }
    }

    #[test]
    fn each_bad_entry_is_refused_and_the_rest_are_extracted() {
        let json: &[u8] = br#"{"files":{"a.txt":{"size":3,"offset":"0"},"big.txt":{"size":9999,"offset":"0"},"..":{"files":{"x.txt":{"size":3,"offset":"0"}}},"nooffset.txt":{"size":3},"link.js":{"link":"../../etc/passwd"},"z.txt":{"size":3,"offset":"0"}}}"#;
        let bytes: Vec<u8> = pickle(json, b"abc");
        let cfg: CarveConfig = CarveConfig::default();
        let report: CarveReport = extract(&bytes, &cfg).expect("bad entries do not abort");
        let extracted: Vec<&str> = report
            .assets
            .iter()
            .map(|asset: &RecoveredAsset| asset.path.as_str())
            .collect();
        assert_eq!(extracted, vec!["a.txt", "z.txt"]);
        let refused: Vec<&str> = report
            .refusals
            .iter()
            .map(|refusal: &EntryRefusal| refusal.path.as_str())
            .collect();
        assert_eq!(
            refused,
            vec!["../x.txt", "big.txt", "link.js", "nooffset.txt"]
        );
        assert_eq!(report.declared, 6);
        assert_eq!(report.recovered, 2);
        assert!(report.coverage() < 1.0);
    }

    #[test]
    fn a_case_colliding_pair_an_aliasing_entry_and_an_overlong_name_are_each_refused() {
        let long_dir: String = "d".repeat(5000);
        let json: String = format!(
            r#"{{"files":{{"a.txt":{{"size":3,"offset":"0"}},"A.TXT":{{"size":3,"offset":"0"}},"b.txt":{{"size":3,"offset":"3"}},"zz.bin":{{"size":6,"offset":"0"}},"{long_dir}":{{"files":{{"x":{{"size":1,"offset":"0"}},"y":{{"size":1,"offset":"0"}}}}}}}}}}"#
        );
        let bytes: Vec<u8> = pickle(json.as_bytes(), b"abcdef");
        let mut cfg: CarveConfig = CarveConfig::default();
        cfg.quota.max_aggregate_ratio = 1;
        let report: CarveReport = extract(&bytes, &cfg).expect("bad entries do not abort");
        let extracted: Vec<&str> = report
            .assets
            .iter()
            .map(|asset: &RecoveredAsset| asset.path.as_str())
            .collect();
        assert_eq!(extracted, vec!["b.txt"]);
        assert_eq!(report.refusals.len(), 5, "{:?}", report.refusals);
        assert_eq!(report.refusals[0].path, "A.TXT");
        assert_eq!(report.refusals[1].path, "a.txt");
        for refusal in &report.refusals[2..4] {
            assert_eq!(refusal.path.len(), MAX_ENTRY_PATH_BYTES);
            assert!(refusal.reason.contains("not a safe relative path"));
        }
        assert_eq!(report.refusals[4].path, "zz.bin");
        assert!(report.refusals[4].reason.contains("data region"));
        assert_eq!(report.declared, 6);
        assert_eq!(report.recovered, 1);
    }

    #[test]
    fn a_table_past_the_entry_quota_is_a_typed_error() {
        let json: &[u8] = br#"{"files":{"a":{"size":0,"offset":"0"},"b":{"size":0,"offset":"0"},"c":{"size":0,"offset":"0"}}}"#;
        let bytes: Vec<u8> = pickle(json, b"");
        let mut cfg: CarveConfig = CarveConfig::default();
        cfg.quota.max_entries = 2;
        assert!(matches!(
            extract(&bytes, &cfg),
            Err(Error::Quota { entry, .. }) if entry == "c"
        ));
    }
}
