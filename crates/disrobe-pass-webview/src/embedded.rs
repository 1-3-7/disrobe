use std::collections::BTreeSet;

use disrobe_binfmt::containers::bare_stream::{detect_gzip, detect_zstd};
use disrobe_binfmt::{QuotaGuard, sanitize_entry_path};
use sha2::{Digest, Sha256};

use disrobe_binfmt::ExtractionQuota;

use crate::CarveConfig;
use crate::decompress::{Decoded, decode_blob};
use crate::error::{Error, Result};
use crate::model::{Compression, IntegrityStatus, RecoveredAsset};
use crate::resolve::SectionMap;

pub(crate) const MIN_CONSECUTIVE: usize = 8;
const MAX_PATH_LEN: usize = 4096;
const MAX_RECORD_BLOB: usize = 256 * 1024 * 1024;
const HASH_LEN: usize = 16;
const MAX_HASH_HAMMING: usize = 1;
const COHERENT_PATH_PERCENT: usize = 80;
const COMPRESSED_ANCHOR_PERCENT: usize = 80;
const HASH_VERIFIED_SCORE: u64 = 1_000_000_000;
const COMPRESSED_ANCHOR_SCORE: u64 = 1_000_000;
const HASH_BUDGET_MULT: u64 = 16;
const HASH_BUDGET_FLOOR: u64 = 1 << 20;
const MAX_SCAN_RECORDS: usize = 2_000_000;

#[derive(Debug, Clone, Copy)]
enum FieldOrder {
    PtrLenPtrLen,
    PtrPtrLenLen,
}

const ORDERS: [FieldOrder; 2] = [FieldOrder::PtrLenPtrLen, FieldOrder::PtrPtrLenLen];

struct Record<'a> {
    name: &'a str,
    is_dir: bool,
    data: &'a [u8],
    hash: Option<[u8; HASH_LEN]>,
}

#[derive(Debug)]
pub(crate) struct Assembled {
    pub(crate) assets: Vec<RecoveredAsset>,
    pub(crate) directories: Vec<String>,
    pub(crate) declared: usize,
    pub(crate) recovered: usize,
}

pub(crate) fn scan(bytes: &[u8], cfg: &CarveConfig) -> Result<Assembled> {
    let maps: Vec<SectionMap<'_>> = SectionMap::build_slices(bytes)?;
    let mut candidates: Vec<Vec<Record<'_>>> = Vec::new();
    let mut budget: u64 = cfg.max_table_probes;
    let mut retained: usize = 0;
    for map in &maps {
        let ptr: usize = map.ptr_size();
        let strides: &[usize] = strides_for(ptr);
        for (span_va, span_vsize) in map.scan_ranges() {
            for order in ORDERS {
                for &stride in strides {
                    collect_runs(
                        map,
                        span_va,
                        span_vsize,
                        stride,
                        order,
                        ptr,
                        &mut budget,
                        &mut retained,
                        MAX_SCAN_RECORDS,
                        &mut candidates,
                    );
                }
            }
        }
    }
    let mut hash_budget: u64 = (bytes.len() as u64)
        .saturating_mul(HASH_BUDGET_MULT)
        .max(HASH_BUDGET_FLOOR);
    let mut best: Option<(u64, &Vec<Record<'_>>)> = None;
    for run in &candidates {
        let value: u64 = score_run(run, &mut hash_budget);
        if value > 0 && best.is_none_or(|(current, _): (u64, _)| value > current) {
            best = Some((value, run));
        }
    }
    let (_, winner): (u64, &Vec<Record<'_>>) =
        best.ok_or(Error::NoEmbeddedTable(MIN_CONSECUTIVE))?;
    assemble(winner, cfg)
}

const fn strides_for(ptr: usize) -> &'static [usize] {
    if ptr == 8 {
        &[48, 40, 32]
    } else {
        &[32, 24, 16]
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_runs<'a>(
    map: &SectionMap<'a>,
    span_va: u64,
    span_vsize: u64,
    stride: usize,
    order: FieldOrder,
    ptr: usize,
    budget: &mut u64,
    retained: &mut usize,
    max_records: usize,
    out: &mut Vec<Vec<Record<'a>>>,
) {
    let Some(span_end) = span_va.checked_add(span_vsize) else {
        return;
    };
    let stride_u64: u64 = stride as u64;
    let mut cursor: u64 = align_up(span_va, ptr as u64);
    while cursor
        .checked_add(stride_u64)
        .is_some_and(|end: u64| end <= span_end)
    {
        if *budget == 0 || *retained >= max_records {
            return;
        }
        *budget -= 1;
        let Some(first) = validate(map, cursor, stride, order, ptr) else {
            let Some(next) = cursor.checked_add(ptr as u64) else {
                return;
            };
            cursor = next;
            continue;
        };
        let mut run: Vec<Record<'a>> = vec![first];
        let mut next: u64 = match cursor.checked_add(stride_u64) {
            Some(value) => value,
            None => break,
        };
        while next
            .checked_add(stride_u64)
            .is_some_and(|end: u64| end <= span_end)
        {
            if *budget == 0 {
                break;
            }
            *budget -= 1;
            let Some(record) = validate(map, next, stride, order, ptr) else {
                break;
            };
            run.push(record);
            let Some(step) = next.checked_add(stride_u64) else {
                break;
            };
            next = step;
        }
        if run.len() >= MIN_CONSECUTIVE
            && let Some(total) = retained.checked_add(run.len())
            && total <= max_records
        {
            *retained = total;
            out.push(run);
        }
        cursor = next.max(cursor.saturating_add(ptr as u64));
    }
}

fn validate<'a>(
    map: &SectionMap<'a>,
    base: u64,
    stride: usize,
    order: FieldOrder,
    ptr: usize,
) -> Option<Record<'a>> {
    let (name_ptr, name_len, data_ptr, data_len): (u64, u64, u64, u64) = match order {
        FieldOrder::PtrLenPtrLen => (
            map.read_ptr(base)?,
            map.read_word(word_va(base, 1, ptr)?)?,
            map.read_ptr(word_va(base, 2, ptr)?)?,
            map.read_word(word_va(base, 3, ptr)?)?,
        ),
        FieldOrder::PtrPtrLenLen => (
            map.read_ptr(base)?,
            map.read_word(word_va(base, 2, ptr)?)?,
            map.read_ptr(word_va(base, 1, ptr)?)?,
            map.read_word(word_va(base, 3, ptr)?)?,
        ),
    };
    let name_len_usize: usize = usize::try_from(name_len).ok()?;
    if name_len_usize == 0 || name_len_usize > MAX_PATH_LEN {
        return None;
    }
    let name_bytes: &'a [u8] = map.slice(name_ptr, name_len_usize)?;
    let name: &'a str = valid_path(name_bytes)?;
    let data_len_usize: usize = usize::try_from(data_len).ok()?;
    if data_len_usize > MAX_RECORD_BLOB {
        return None;
    }
    let is_dir: bool = name.ends_with('/');
    let data: &'a [u8] = if data_len_usize == 0 {
        &[]
    } else {
        map.slice(data_ptr, data_len_usize)?
    };
    let hash: Option<[u8; HASH_LEN]> = read_hash(map, base, stride, ptr);
    Some(Record {
        name,
        is_dir,
        data,
        hash,
    })
}

fn read_hash(map: &SectionMap<'_>, base: u64, stride: usize, ptr: usize) -> Option<[u8; HASH_LEN]> {
    if stride < ptr.checked_mul(4)?.checked_add(HASH_LEN)? {
        return None;
    }
    let hash_va: u64 = word_va(base, 4, ptr)?;
    let bytes: &[u8] = map.slice(hash_va, HASH_LEN)?;
    bytes.try_into().ok()
}

fn valid_path(bytes: &[u8]) -> Option<&str> {
    let text: &str = core::str::from_utf8(bytes).ok()?;
    if text.is_empty() || text.starts_with('\\') || text.starts_with("//") {
        return None;
    }
    if text
        .chars()
        .any(|c: char| (c as u32) < 0x20 || c == '\u{7f}')
    {
        return None;
    }
    if text.chars().all(char::is_whitespace) {
        return None;
    }
    Some(text)
}

fn score_run(run: &[Record<'_>], hash_budget: &mut u64) -> u64 {
    if run.len() < MIN_CONSECUTIVE {
        return 0;
    }
    if hash_verified(run, hash_budget) {
        return HASH_VERIFIED_SCORE + run.len() as u64;
    }
    if !path_coherent(run) {
        return 0;
    }
    if compression_anchored(run) {
        return COMPRESSED_ANCHOR_SCORE + run.len() as u64;
    }
    run.len() as u64
}

fn compression_anchored(run: &[Record<'_>]) -> bool {
    let mut blobs: usize = 0;
    let mut framed: usize = 0;
    for record in run {
        if record.is_dir || record.data.is_empty() {
            continue;
        }
        blobs += 1;
        if detect_zstd(record.data) || detect_gzip(record.data) {
            framed += 1;
        }
    }
    blobs >= MIN_CONSECUTIVE && framed * 100 >= blobs * COMPRESSED_ANCHOR_PERCENT
}

fn hash_verified(run: &[Record<'_>], budget: &mut u64) -> bool {
    let mut checked: usize = 0;
    for record in run {
        if record.is_dir || record.data.is_empty() {
            continue;
        }
        let Some(stored) = record.hash else {
            return false;
        };
        let Some(remaining) = budget.checked_sub(record.data.len() as u64) else {
            return false;
        };
        *budget = remaining;
        let digest: [u8; 32] = Sha256::digest(record.data).into();
        let differing: usize = (0..HASH_LEN)
            .filter(|&i: &usize| stored[i] != digest[i])
            .count();
        if differing > MAX_HASH_HAMMING {
            return false;
        }
        checked += 1;
    }
    checked >= 1
}

fn path_coherent(run: &[Record<'_>]) -> bool {
    let mut pathlike: usize = 0;
    for record in run {
        if record.name.chars().any(char::is_whitespace) {
            return false;
        }
        if record.name.contains('/') || record.name.contains('.') {
            pathlike += 1;
        }
    }
    pathlike * 100 >= run.len() * COHERENT_PATH_PERCENT
}

fn assemble(run: &[Record<'_>], cfg: &CarveConfig) -> Result<Assembled> {
    let mut guard: QuotaGuard = QuotaGuard::new(cfg.quota);
    let mut assets: Vec<RecoveredAsset> = Vec::new();
    let mut directories: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut declared: usize = 0;
    let mut recovered: usize = 0;
    for record in run {
        if record.is_dir {
            if let Some(safe) = normalize_key(record.name.trim_end_matches('/')) {
                directories.insert(safe);
            }
            continue;
        }
        let Some(safe) = normalize_key(record.name) else {
            declared += 1;
            continue;
        };
        if !seen.insert(safe.clone()) {
            continue;
        }
        declared += 1;
        let (bytes, compression): (Vec<u8>, Compression) =
            match decode_blob(record.data, decode_cap(record.data.len(), &cfg.quota)) {
                Decoded::Bytes { data, compression } => (data, compression),
                Decoded::QuotaRefused { reason, .. } => {
                    return Err(Error::Quota {
                        entry: safe,
                        reason: format!(
                            "{reason}, capped by the per-entry expansion ratio {}",
                            cfg.quota.max_per_entry_ratio
                        ),
                    });
                }
                Decoded::Corrupt { .. } => continue,
            };
        guard.admit_entry(&safe, bytes.len() as u64, record.data.len() as u64)?;
        recovered += 1;
        assets.push(RecoveredAsset {
            path: safe,
            bytes,
            compression,
            executable: false,
            integrity: IntegrityStatus::Absent,
        });
    }
    Ok(Assembled {
        assets,
        directories: directories.into_iter().collect(),
        declared,
        recovered,
    })
}

fn decode_cap(compressed_len: usize, quota: &ExtractionQuota) -> u64 {
    (compressed_len as u64)
        .saturating_mul(quota.max_per_entry_ratio)
        .min(quota.max_per_entry_uncompressed)
}

fn normalize_key(name: &str) -> Option<String> {
    let root_relative: &str = name.strip_prefix('/').unwrap_or(name);
    sanitize_entry_path(root_relative).ok()
}

fn word_va(base: u64, index: usize, ptr: usize) -> Option<u64> {
    let offset: u64 = u64::try_from(index.checked_mul(ptr)?).ok()?;
    base.checked_add(offset)
}

const fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value.div_ceil(align).saturating_mul(align)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const TEST_VA: u64 = 0x1000;
    const TEST_STRIDE: usize = 32;

    fn hash_prefix(data: &[u8]) -> [u8; HASH_LEN] {
        let digest: [u8; 32] = Sha256::digest(data).into();
        let mut prefix: [u8; HASH_LEN] = [0u8; HASH_LEN];
        prefix.copy_from_slice(&digest[..HASH_LEN]);
        prefix
    }

    #[test]
    fn root_relative_keys_normalize_without_escaping_the_output_root() {
        assert_eq!(
            normalize_key("/assets/index-abc.js").as_deref(),
            Some("assets/index-abc.js"),
            "an embedded asset key is root-relative to the bundle, not to the filesystem"
        );
        assert_eq!(normalize_key("dist/app.js").as_deref(), Some("dist/app.js"));
        assert_eq!(normalize_key("/index.html").as_deref(), Some("index.html"));
        for hostile in [
            "/../../etc/passwd",
            "../outside.js",
            "a/../../b",
            "C:/Windows/win.ini",
            "/C:/Windows/win.ini",
            "/",
            "",
        ] {
            assert!(
                normalize_key(hostile).is_none(),
                "{hostile} must not survive normalization"
            );
        }
    }

    #[test]
    fn valid_path_still_refuses_the_shapes_that_cannot_be_bundle_keys() {
        assert!(valid_path(b"\\\\server\\share").is_none());
        assert!(valid_path(b"//double/slash").is_none());
        assert!(valid_path(b"with\x00nul").is_none());
        assert!(valid_path(b"").is_none());
        assert!(valid_path(b"/assets/app.js").is_some());
    }

    #[test]
    fn compression_anchor_needs_a_full_run_of_framed_blobs() {
        let zstd_frame: [u8; 8] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x00, 0x00];
        let plain: [u8; 8] = [b'p'; 8];
        let framed: Vec<Record<'_>> = (0..MIN_CONSECUTIVE)
            .map(|_index: usize| Record {
                name: "/assets/a.js",
                is_dir: false,
                data: zstd_frame.as_slice(),
                hash: None,
            })
            .collect();
        assert!(compression_anchored(&framed));

        let mut mostly_plain: Vec<Record<'_>> = framed;
        for record in mostly_plain.iter_mut().take(3) {
            record.data = plain.as_slice();
        }
        assert!(
            !compression_anchored(&mostly_plain),
            "a run with three raw blobs is not a compressed asset map"
        );

        let short: Vec<Record<'_>> = (0..MIN_CONSECUTIVE - 1)
            .map(|_index: usize| Record {
                name: "/assets/a.js",
                is_dir: false,
                data: zstd_frame.as_slice(),
                hash: None,
            })
            .collect();
        assert!(
            !compression_anchored(&short),
            "fewer than the consecutive-record floor must not anchor a table"
        );
    }

    #[test]
    fn hash_verified_bounds_aliased_blob_rehashing() {
        let blob: Vec<u8> = vec![0xA5u8; 4096];
        let prefix: [u8; HASH_LEN] = hash_prefix(&blob);
        let records: Vec<Record<'_>> = (0..256usize)
            .map(|_index: usize| Record {
                name: "app.js",
                is_dir: false,
                data: blob.as_slice(),
                hash: Some(prefix),
            })
            .collect();

        let mut tight: u64 = (blob.len() as u64) * 2;
        assert!(
            !hash_verified(&records, &mut tight),
            "an exhausted budget must report the run unverified"
        );
        assert_eq!(
            tight, 0,
            "hashing must stop after two aliased blobs, not re-hash all 256"
        );

        let mut ample: u64 = (blob.len() as u64) * (records.len() as u64);
        assert!(hash_verified(&records, &mut ample));
        assert_eq!(ample, 0);
    }

    fn build_run_groups(groups: usize, per_group: usize) -> Vec<u8> {
        let mut strings: Vec<u8> = Vec::new();
        let mut fields: Vec<(u64, u64, u64, u64)> = Vec::new();
        for group in 0..groups {
            for index in 0..per_group {
                let name: String = format!("dist/g{group}f{index}.js");
                let name_off: usize = strings.len();
                strings.extend_from_slice(name.as_bytes());
                let data_off: usize = strings.len();
                strings.push(b'x');
                fields.push((
                    TEST_VA + name_off as u64,
                    name.len() as u64,
                    TEST_VA + data_off as u64,
                    1,
                ));
            }
            if group + 1 < groups {
                fields.push((0, 0, 0, 0));
            }
        }
        while !strings.len().is_multiple_of(8) {
            strings.push(0);
        }
        let mut buf: Vec<u8> = strings;
        for (name_va, name_len, data_va, data_len) in &fields {
            let start: usize = buf.len();
            buf.extend_from_slice(&name_va.to_le_bytes());
            buf.extend_from_slice(&name_len.to_le_bytes());
            buf.extend_from_slice(&data_va.to_le_bytes());
            buf.extend_from_slice(&data_len.to_le_bytes());
            buf.resize(start + TEST_STRIDE, 0);
        }
        buf
    }

    fn run_totals(cap: usize, buf: &[u8]) -> (usize, usize, usize) {
        let map: SectionMap<'_> =
            SectionMap::from_single_span(buf, TEST_VA, 8, object::Endianness::Little);
        let span_vsize: u64 = buf.len() as u64;
        let mut budget: u64 = 1_000_000;
        let mut retained: usize = 0;
        let mut out: Vec<Vec<Record<'_>>> = Vec::new();
        collect_runs(
            &map,
            TEST_VA,
            span_vsize,
            TEST_STRIDE,
            FieldOrder::PtrLenPtrLen,
            8,
            &mut budget,
            &mut retained,
            cap,
            &mut out,
        );
        let total: usize = out.iter().map(|run: &Vec<Record<'_>>| run.len()).sum();
        (out.len(), total, retained)
    }

    #[test]
    fn collect_runs_caps_total_retained_records() {
        let buf: Vec<u8> = build_run_groups(4, 8);

        let (big_runs, big_total, big_retained): (usize, usize, usize) = run_totals(1000, &buf);
        assert_eq!(
            big_total, 32,
            "an ample cap must retain every validated run"
        );
        assert_eq!(big_runs, 4);
        assert_eq!(big_retained, 32);

        let (_, small_total, small_retained): (usize, usize, usize) = run_totals(20, &buf);
        assert!(
            small_total <= 20,
            "retained records must not exceed the cap, got {small_total}"
        );
        assert_eq!(small_retained, small_total);
        assert!(
            small_total >= 8,
            "the cap must still admit at least one full run"
        );
    }
}
