use std::collections::BTreeSet;

use disrobe_binfmt::containers::bare_stream::{detect_gzip, detect_zstd};
use disrobe_binfmt::{QuotaGuard, sanitize_entry_path};
use sha2::{Digest, Sha256};

use disrobe_binfmt::ExtractionQuota;

use crate::CarveConfig;
use crate::decompress::{CODEC_TRIAL_ORDER, Decoded, claims_blob, decode_blob_anchored};
use crate::error::{Error, Result};
use crate::model::{Compression, IntegrityStatus, RecoveredAsset};
use crate::resolve::SectionMap;

pub(crate) const MIN_CONSECUTIVE: usize = 8;
const MAX_PATH_LEN: usize = 4096;
const MAX_RECORD_BLOB: usize = 256 * 1024 * 1024;
const HASH_LEN: usize = 16;
const MAX_HASH_HAMMING: usize = 1;
const COHERENT_NESTED_PERCENT: usize = 50;
const COHERENT_EXTENSION_PERCENT: usize = 50;
const MAX_EXTENSION_LEN: usize = 16;
const ANCHOR_MIN_MEMBERS: usize = 4;
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
    let mut best: Option<(u64, &[Record<'_>])> = None;
    for run in &candidates {
        let Some((value, window)): Option<(u64, &[Record<'_>])> =
            best_window(run, &mut hash_budget)
        else {
            continue;
        };
        if best.is_none_or(|(current, _): (u64, &[Record<'_>])| value > current) {
            best = Some((value, window));
        }
    }
    let (_, winner): (u64, &[Record<'_>]) = best.ok_or(Error::NoEmbeddedTable(MIN_CONSECUTIVE))?;
    let anchor: Option<Compression> = anchor_codec(winner, cfg);
    assemble(winner, anchor, cfg)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    Neutral,
    Holds,
    Breaks,
}

fn best_window<'a>(
    run: &'a [Record<'a>],
    hash_budget: &mut u64,
) -> Option<(u64, &'a [Record<'a>])> {
    if let Some(window) = hash_window(run, hash_budget) {
        return Some((HASH_VERIFIED_SCORE + window.len() as u64, window));
    }
    if let Some(window) =
        compressed_window(run).filter(|found: &&'a [Record<'a>]| looks_like_asset_tree(found))
    {
        return Some((COMPRESSED_ANCHOR_SCORE + window.len() as u64, window));
    }
    coherent_window(run)
        .filter(|found: &&'a [Record<'a>]| looks_like_asset_tree(found))
        .map(|window: &'a [Record<'a>]| (window.len() as u64, window))
}

fn looks_like_asset_tree(window: &[Record<'_>]) -> bool {
    let files: Vec<&Record<'_>> = window
        .iter()
        .filter(|record: &&Record<'_>| !record.is_dir)
        .collect();
    if files.len() < MIN_CONSECUTIVE {
        return false;
    }
    let nested: usize = files
        .iter()
        .filter(|record: &&&Record<'_>| record.name.contains('/'))
        .count();
    let extended: usize = files
        .iter()
        .filter(|record: &&&Record<'_>| has_file_extension(record.name))
        .count();
    nested * 100 >= files.len() * COHERENT_NESTED_PERCENT
        && extended * 100 >= files.len() * COHERENT_EXTENSION_PERCENT
}

fn has_file_extension(name: &str) -> bool {
    let leaf: &str = name.rsplit_once('/').map_or(name, |(_, tail)| tail);
    leaf.rsplit_once('.')
        .is_some_and(|(stem, extension): (&str, &str)| {
            !stem.is_empty() && !extension.is_empty() && extension.len() <= MAX_EXTENSION_LEN
        })
}

fn longest_window<'a>(
    run: &'a [Record<'a>],
    min_holds: usize,
    mut classify: impl FnMut(&Record<'a>) -> Evidence,
) -> Option<&'a [Record<'a>]> {
    let mut best: Option<(usize, usize)> = None;
    let mut start: usize = 0;
    let mut holds: usize = 0;
    let take = |span: (usize, usize), holds: usize, best: &mut Option<(usize, usize)>| {
        let len: usize = span.1 - span.0;
        if holds < min_holds || len < MIN_CONSECUTIVE {
            return;
        }
        if best.is_none_or(|(from, to): (usize, usize)| len > to - from) {
            *best = Some(span);
        }
    };
    for (index, record) in run.iter().enumerate() {
        match classify(record) {
            Evidence::Neutral => {}
            Evidence::Holds => holds += 1,
            Evidence::Breaks => {
                take((start, index), holds, &mut best);
                start = index + 1;
                holds = 0;
            }
        }
    }
    take((start, run.len()), holds, &mut best);
    best.and_then(|(from, to): (usize, usize)| run.get(from..to))
}

fn compressed_window<'a>(run: &'a [Record<'a>]) -> Option<&'a [Record<'a>]> {
    longest_window(run, MIN_CONSECUTIVE, |record: &Record<'a>| {
        if record.is_dir || record.data.is_empty() {
            return Evidence::Neutral;
        }
        if detect_zstd(record.data) || detect_gzip(record.data) {
            Evidence::Holds
        } else {
            Evidence::Breaks
        }
    })
}

fn hash_window<'a>(run: &'a [Record<'a>], budget: &mut u64) -> Option<&'a [Record<'a>]> {
    longest_window(run, 1, |record: &Record<'a>| {
        if record.is_dir || record.data.is_empty() {
            return Evidence::Neutral;
        }
        let Some(stored) = record.hash else {
            return Evidence::Breaks;
        };
        let Some(remaining) = budget.checked_sub(record.data.len() as u64) else {
            return Evidence::Breaks;
        };
        *budget = remaining;
        let digest: [u8; 32] = Sha256::digest(record.data).into();
        let differing: usize = (0..HASH_LEN)
            .filter(|&i: &usize| stored[i] != digest[i])
            .count();
        if differing > MAX_HASH_HAMMING {
            Evidence::Breaks
        } else {
            Evidence::Holds
        }
    })
}

fn coherent_window<'a>(run: &'a [Record<'a>]) -> Option<&'a [Record<'a>]> {
    longest_window(run, MIN_CONSECUTIVE, |record: &Record<'a>| {
        if record.name.chars().any(char::is_whitespace) {
            Evidence::Breaks
        } else {
            Evidence::Holds
        }
    })
}

fn anchor_codec(window: &[Record<'_>], cfg: &CarveConfig) -> Option<Compression> {
    let mut counts: [usize; CODEC_TRIAL_ORDER.len()] = [0; CODEC_TRIAL_ORDER.len()];
    for record in window {
        if record.is_dir || record.data.is_empty() {
            continue;
        }
        for (slot, codec) in counts.iter_mut().zip(CODEC_TRIAL_ORDER) {
            if claims_blob(
                codec,
                record.data,
                decode_cap(record.data.len(), &cfg.quota),
            ) {
                *slot += 1;
                break;
            }
        }
    }
    let claimed: usize = counts.iter().sum();
    counts
        .iter()
        .zip(CODEC_TRIAL_ORDER)
        .find(|(count, _): &(&usize, Compression)| {
            **count >= ANCHOR_MIN_MEMBERS && **count == claimed
        })
        .map(|(_, codec): (&usize, Compression)| codec)
}

fn assemble(
    run: &[Record<'_>],
    anchor: Option<Compression>,
    cfg: &CarveConfig,
) -> Result<Assembled> {
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
        let (bytes, compression): (Vec<u8>, Compression) = match decode_blob_anchored(
            record.data,
            decode_cap(record.data.len(), &cfg.quota),
            anchor,
        ) {
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

    fn framed_record(data: &'static [u8]) -> Record<'static> {
        Record {
            name: "/assets/a.js",
            is_dir: false,
            data,
            hash: None,
        }
    }

    const ZSTD_FRAME: [u8; 8] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x00, 0x00];
    const PLAIN_BLOB: [u8; 8] = [b'p'; 8];

    #[test]
    fn the_compressed_anchor_takes_the_framed_stretch_and_leaves_the_raw_tail() {
        let framed: Vec<Record<'_>> = (0..MIN_CONSECUTIVE)
            .map(|_index: usize| framed_record(ZSTD_FRAME.as_slice()))
            .collect();
        assert_eq!(
            compressed_window(&framed).map(<[Record<'_>]>::len),
            Some(MIN_CONSECUTIVE)
        );

        let mut with_tail: Vec<Record<'_>> = framed;
        with_tail.extend((0..4).map(|_index: usize| framed_record(PLAIN_BLOB.as_slice())));
        assert_eq!(
            compressed_window(&with_tail).map(<[Record<'_>]>::len),
            Some(MIN_CONSECUTIVE),
            "a raw record past the table must end the window rather than disqualify the table"
        );

        let leading_raw: Vec<Record<'_>> = (0..3)
            .map(|_index: usize| framed_record(PLAIN_BLOB.as_slice()))
            .chain((0..4).map(|_index: usize| framed_record(ZSTD_FRAME.as_slice())))
            .collect();
        assert!(
            compressed_window(&leading_raw).is_none(),
            "fewer framed blobs than the consecutive-record floor must not anchor a table"
        );
    }

    #[test]
    fn the_hash_anchor_stops_at_the_first_record_whose_hash_does_not_describe_its_bytes() {
        let blob: Vec<u8> = vec![0xA5u8; 64];
        let prefix: [u8; HASH_LEN] = hash_prefix(&blob);
        let mut records: Vec<Record<'_>> = (0..12usize)
            .map(|_index: usize| Record {
                name: "app.js",
                is_dir: false,
                data: blob.as_slice(),
                hash: Some(prefix),
            })
            .collect();
        let mut ample: u64 = 1 << 20;
        assert_eq!(
            hash_window(&records, &mut ample).map(<[Record<'_>]>::len),
            Some(12)
        );

        records[9].hash = Some([0u8; HASH_LEN]);
        let mut second: u64 = 1 << 20;
        assert_eq!(
            hash_window(&records, &mut second).map(<[Record<'_>]>::len),
            Some(9),
            "the window must end where the self-describing hash stops, not swallow the neighbour"
        );
    }

    #[test]
    fn hash_matching_stops_once_the_budget_is_spent() {
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
            hash_window(&records, &mut tight).is_none(),
            "an exhausted budget must not lock a window it never verified"
        );
        assert_eq!(
            tight, 0,
            "hashing must stop after two aliased blobs, not re-hash all 256"
        );
    }

    #[test]
    fn a_flat_name_list_is_not_a_frontend_tree() {
        let dlls: Vec<Record<'_>> = ["user32.dll", "gdi32.dll", "ole32.dll", "shell32.dll"]
            .into_iter()
            .cycle()
            .take(24)
            .map(|name: &'static str| Record {
                name,
                is_dir: false,
                data: PLAIN_BLOB.as_slice(),
                hash: None,
            })
            .collect();
        let mut budget: u64 = 1 << 20;
        assert!(
            best_window(&dlls, &mut budget).is_none(),
            "a run of flat names carries no directory structure and must not lock as an asset map"
        );

        let mime: Vec<Record<'_>> = ["application/wasm", "text/html", "image/png", "video/mp4"]
            .into_iter()
            .cycle()
            .take(24)
            .map(|name: &'static str| Record {
                name,
                is_dir: false,
                data: PLAIN_BLOB.as_slice(),
                hash: None,
            })
            .collect();
        assert!(
            best_window(&mime, &mut budget).is_none(),
            "a media-type table is nested but carries no file extensions, so it is not a frontend \
             tree even though it is longer than one"
        );

        let tree: Vec<Record<'_>> = (0..12usize)
            .map(|_index: usize| Record {
                name: "dist/assets/app.js",
                is_dir: false,
                data: PLAIN_BLOB.as_slice(),
                hash: None,
            })
            .collect();
        assert_eq!(
            best_window(&tree, &mut budget).map(|(_, window): (u64, &[Record<'_>])| window.len()),
            Some(12)
        );
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
