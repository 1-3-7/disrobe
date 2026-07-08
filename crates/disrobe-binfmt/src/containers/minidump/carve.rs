use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::pe_emit::{self, PeEmitReport};
use super::{MAX_SIZE_OF_IMAGE, MinidumpFile, MinidumpModule, err};

const PAGE_SIZE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbsentReason {
    NotPresentInDump,
    TruncatedDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbsentRange {
    pub start_va: u64,
    pub end_va: u64,
    pub reason: AbsentReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub size_of_image: u64,
    pub covered_bytes: u64,
    pub truncated_bytes: u64,
    pub absent_bytes: u64,
    pub coverage_ratio: f64,
    pub complete: bool,
    pub headers_present: bool,
    pub overlap_detected: bool,
    pub page_size: u64,
    pub pages_total: u64,
    pub pages_covered: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedModule {
    pub base_of_image: u64,
    pub size_of_image: u64,
    pub module_name: String,
    pub image: Vec<u8>,
    pub coverage: CoverageReport,
    pub absent_ranges: Vec<AbsentRange>,
    pub pe_emit: Option<PeEmitReport>,
    pub notes: Vec<String>,
}

pub fn carve_module(
    file: &MinidumpFile,
    dump: &[u8],
    module: &MinidumpModule,
    cap: u64,
) -> Result<CarvedModule> {
    let size: u64 = u64::from(module.size_of_image);
    if size == 0 {
        return Err(err(format!(
            "minidump: module {} declares SizeOfImage of zero",
            module.file_name()
        )));
    }
    let bound: u64 = cap.min(MAX_SIZE_OF_IMAGE);
    if size > bound {
        return Err(err(format!(
            "minidump: module {} SizeOfImage {size} exceeds materialization bound {bound}",
            module.file_name()
        )));
    }
    let base: u64 = module.base_of_image;
    let window_end: u64 = base
        .checked_add(size)
        .ok_or_else(|| err("minidump: module virtual-address window overflows u64"))?;
    let size_usize: usize = usize::try_from(size)
        .map_err(|_e: std::num::TryFromIntError| err("minidump: module size overflows usize"))?;

    let mut image: Vec<u8> = vec![0u8; size_usize];
    let mut covered: Vec<(u64, u64)> = Vec::new();
    let mut truncated: Vec<(u64, u64)> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut overlap_detected: bool = false;

    for region in &file.memory_regions {
        let region_end: u64 = match region.start_va.checked_add(region.data_size) {
            Some(value) => value,
            None => continue,
        };
        let overlap_start: u64 = region.start_va.max(base);
        let overlap_end: u64 = region_end.min(window_end);
        if overlap_start >= overlap_end {
            continue;
        }
        let module_start: u64 = overlap_start - base;
        let module_end: u64 = overlap_end - base;
        let src_skip: u64 = overlap_start - region.start_va;
        let available_here: u64 = region.file_available.saturating_sub(src_skip);

        let frees: Vec<(u64, u64)> = subtract(module_start, module_end, &covered);
        let free_total: u64 = frees.iter().map(|&(a, b): &(u64, u64)| b - a).sum();
        if free_total < module_end - module_start {
            overlap_detected = true;
        }

        for (free_start, free_end) in frees {
            let want: u64 = free_end - free_start;
            let sub_skip: u64 = free_start - module_start;
            let available: u64 = available_here.saturating_sub(sub_skip);
            let copy_len: u64 = want.min(available);
            if copy_len > 0 {
                let file_start: u64 = region
                    .file_offset
                    .checked_add(src_skip)
                    .and_then(|value: u64| value.checked_add(sub_skip))
                    .ok_or_else(|| err("minidump: source file offset overflow"))?;
                copy_region(
                    dump, &mut image, file_start, free_start, copy_len, &mut notes,
                );
                insert_interval(&mut covered, free_start, free_start + copy_len);
            }
            if copy_len < want {
                truncated.push((free_start + copy_len, free_end));
            }
        }
    }

    let truncated_merged: Vec<(u64, u64)> = merged(truncated);
    let covered_bytes: u64 = covered.iter().map(|&(a, b): &(u64, u64)| b - a).sum();
    let gaps: Vec<(u64, u64)> = subtract(0, size, &covered);
    let mut absent_ranges: Vec<AbsentRange> = Vec::new();
    let mut truncated_bytes: u64 = 0;
    for (gap_start, gap_end) in gaps {
        for (a, b) in intersect(gap_start, gap_end, &truncated_merged) {
            truncated_bytes += b - a;
            absent_ranges.push(AbsentRange {
                start_va: base + a,
                end_va: base + b,
                reason: AbsentReason::TruncatedDescriptor,
            });
        }
        for (a, b) in subtract(gap_start, gap_end, &truncated_merged) {
            absent_ranges.push(AbsentRange {
                start_va: base + a,
                end_va: base + b,
                reason: AbsentReason::NotPresentInDump,
            });
        }
    }
    absent_ranges.sort_by_key(|range: &AbsentRange| range.start_va);

    let headers_present: bool = covered
        .first()
        .is_some_and(|&(start, _): &(u64, u64)| start == 0)
        && crate::structural::locate_pe_header(&image).is_some();

    let pe_emit: Option<PeEmitReport> = if headers_present {
        let report: PeEmitReport = pe_emit::emit(&mut image, base);
        Some(report)
    } else {
        notes.push(
            "minidump: PE headers (page 0) absent from the dump; emitting the raw carved window without section-table reconstruction".to_owned(),
        );
        None
    };

    let absent_bytes: u64 = size - covered_bytes;
    let pages_total: u64 = size.div_ceil(PAGE_SIZE);
    let pages_covered: u64 = count_covered_pages(&covered, size);
    let coverage_ratio: f64 = covered_bytes as f64 / size as f64;

    let coverage: CoverageReport = CoverageReport {
        size_of_image: size,
        covered_bytes,
        truncated_bytes,
        absent_bytes,
        coverage_ratio,
        complete: covered_bytes == size,
        headers_present,
        overlap_detected,
        page_size: PAGE_SIZE,
        pages_total,
        pages_covered,
    };

    Ok(CarvedModule {
        base_of_image: base,
        size_of_image: size,
        module_name: module.file_name(),
        image,
        coverage,
        absent_ranges,
        pe_emit,
        notes,
    })
}

fn copy_region(
    dump: &[u8],
    image: &mut [u8],
    file_start: u64,
    module_start: u64,
    copy_len: u64,
    notes: &mut Vec<String>,
) {
    let (Ok(src_off), Ok(dst_off), Ok(len)): (
        core::result::Result<usize, _>,
        core::result::Result<usize, _>,
        core::result::Result<usize, _>,
    ) = (
        usize::try_from(file_start),
        usize::try_from(module_start),
        usize::try_from(copy_len),
    ) else {
        notes.push("minidump: memory range offset overflows usize; skipped".to_owned());
        return;
    };
    let (Some(src), Some(dst)): (Option<&[u8]>, Option<&mut [u8]>) = (
        dump.get(src_off..src_off + len),
        image.get_mut(dst_off..dst_off + len),
    ) else {
        notes.push("minidump: memory range slice out of bounds; skipped".to_owned());
        return;
    };
    dst.copy_from_slice(src);
}

fn subtract(start: u64, end: u64, covered: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut result: Vec<(u64, u64)> = Vec::new();
    if start >= end {
        return result;
    }
    let mut cursor: u64 = start;
    for &(a, b) in covered {
        if b <= cursor {
            continue;
        }
        if a >= end {
            break;
        }
        if a > cursor {
            result.push((cursor, a.min(end)));
        }
        cursor = cursor.max(b);
        if cursor >= end {
            break;
        }
    }
    if cursor < end {
        result.push((cursor, end));
    }
    result
}

fn intersect(start: u64, end: u64, set: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &(a, b) in set {
        let lo: u64 = a.max(start);
        let hi: u64 = b.min(end);
        if lo < hi {
            out.push((lo, hi));
        }
    }
    out
}

fn insert_interval(covered: &mut Vec<(u64, u64)>, a: u64, b: u64) {
    if a >= b {
        return;
    }
    covered.push((a, b));
    *covered = merged(std::mem::take(covered));
}

fn merged(mut intervals: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    if intervals.is_empty() {
        return intervals;
    }
    intervals.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        if let Some(last) = out.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        out.push((start, end));
    }
    out
}

fn count_covered_pages(covered: &[(u64, u64)], size: u64) -> u64 {
    let total_pages: u64 = size.div_ceil(PAGE_SIZE);
    let mut covered_pages: u64 = 0;
    let mut idx: usize = 0;
    for page in 0..total_pages {
        let page_start: u64 = page * PAGE_SIZE;
        let page_end: u64 = ((page + 1) * PAGE_SIZE).min(size);
        while idx < covered.len() && covered[idx].1 <= page_start {
            idx += 1;
        }
        if idx < covered.len() && covered[idx].0 <= page_start && covered[idx].1 >= page_end {
            covered_pages += 1;
        }
    }
    covered_pages
}
