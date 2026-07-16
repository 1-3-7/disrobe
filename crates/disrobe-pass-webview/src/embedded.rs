use std::collections::BTreeSet;

use disrobe_binfmt::{QuotaGuard, sanitize_entry_path};
use sha2::{Digest, Sha256};

use crate::CarveConfig;
use crate::decompress::decode_blob;
use crate::error::{Error, Result};
use crate::model::{Compression, IntegrityStatus, RecoveredAsset};
use crate::resolve::SectionMap;

pub(crate) const MIN_CONSECUTIVE: usize = 8;
const MAX_PATH_LEN: usize = 4096;
const MAX_RECORD_BLOB: usize = 256 * 1024 * 1024;
const HASH_LEN: usize = 16;
const MAX_HASH_HAMMING: usize = 1;
const COHERENT_PATH_PERCENT: usize = 80;
const HASH_VERIFIED_SCORE: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy)]
enum FieldOrder {
    PtrLenPtrLen,
    PtrPtrLenLen,
}

const ORDERS: [FieldOrder; 2] = [FieldOrder::PtrLenPtrLen, FieldOrder::PtrPtrLenLen];

struct Record<'a> {
    name: String,
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
    let map: SectionMap<'_> = SectionMap::build(bytes)?;
    let ptr: usize = map.ptr_size();
    let strides: &[usize] = strides_for(ptr);
    let mut candidates: Vec<Vec<Record<'_>>> = Vec::new();
    let mut budget: u64 = cfg.max_table_probes;
    for (span_va, span_vsize) in map.scan_ranges() {
        for order in ORDERS {
            for &stride in strides {
                collect_runs(
                    &map,
                    span_va,
                    span_vsize,
                    stride,
                    order,
                    ptr,
                    &mut budget,
                    &mut candidates,
                );
            }
        }
    }
    let mut best: Option<(u64, &Vec<Record<'_>>)> = None;
    for run in &candidates {
        let value: u64 = score_run(run);
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
        if *budget == 0 {
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
        if run.len() >= MIN_CONSECUTIVE {
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
    let name_bytes: &[u8] = map.slice(name_ptr, name_len_usize)?;
    let name: String = valid_path(name_bytes)?;
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

fn valid_path(bytes: &[u8]) -> Option<String> {
    let text: &str = core::str::from_utf8(bytes).ok()?;
    if text.is_empty() || text.starts_with('/') || text.starts_with('\\') {
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
    Some(text.to_owned())
}

fn score_run(run: &[Record<'_>]) -> u64 {
    if run.len() < MIN_CONSECUTIVE {
        return 0;
    }
    if hash_verified(run) {
        return HASH_VERIFIED_SCORE + run.len() as u64;
    }
    if path_coherent(run) {
        return run.len() as u64;
    }
    0
}

fn hash_verified(run: &[Record<'_>]) -> bool {
    let mut checked: usize = 0;
    for record in run {
        if record.is_dir || record.data.is_empty() {
            continue;
        }
        let Some(stored) = record.hash else {
            return false;
        };
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
            let trimmed: &str = record.name.trim_end_matches('/');
            if let Ok(safe) = sanitize_entry_path(trimmed) {
                directories.insert(safe);
            }
            continue;
        }
        let Ok(safe) = sanitize_entry_path(&record.name) else {
            declared += 1;
            continue;
        };
        if !seen.insert(safe.clone()) {
            continue;
        }
        declared += 1;
        let (bytes, compression): (Vec<u8>, Compression) =
            decode_blob(record.data, cfg.quota.max_per_entry_uncompressed);
        guard.admit_entry(&safe, record.data.len() as u64, bytes.len() as u64)?;
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
