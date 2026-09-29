use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::pe_emit::{self, PeEmitReport};
use super::{MAX_SIZE_OF_IMAGE, MinidumpFile, MinidumpModule, err};

const PAGE_SIZE: u64 = 4096;
const MAX_CARVE_STEPS: u64 = 1 << 26;

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
    let mut cover: CoverSet = CoverSet::default();
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

        let frees: Vec<(u64, u64)> = cover.gaps(module_start, module_end)?;
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
                cover.insert(free_start, free_start + copy_len)?;
            }
            if copy_len < want {
                cover.charge(1)?;
                truncated.push((free_start + copy_len, free_end));
            }
        }
    }

    let truncated_merged: Vec<(u64, u64)> = merged(truncated);
    let gaps: Vec<(u64, u64)> = cover.gaps(0, size)?;
    let covered: Vec<(u64, u64)> = cover.spans.into_iter().collect();
    let covered_bytes: u64 = covered.iter().map(|&(a, b): &(u64, u64)| b - a).sum();
    let (absent_ranges, truncated_bytes): (Vec<AbsentRange>, u64) =
        classify_gaps(&gaps, &truncated_merged, base);

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

#[derive(Debug, Default)]
struct CoverSet {
    spans: BTreeMap<u64, u64>,
    steps: u64,
}

impl CoverSet {
    fn charge(&mut self, steps: u64) -> Result<()> {
        self.steps = self.steps.saturating_add(steps);
        if self.steps > MAX_CARVE_STEPS {
            return Err(err(format!(
                "minidump: carving exceeded its work budget of {MAX_CARVE_STEPS} interval steps"
            )));
        }
        Ok(())
    }

    fn gaps(&mut self, start: u64, end: u64) -> Result<Vec<(u64, u64)>> {
        let mut result: Vec<(u64, u64)> = Vec::new();
        if start >= end {
            return Ok(result);
        }
        self.charge(1)?;
        let mut cursor: u64 = start;
        if let Some((_, &before_end)) = self.spans.range(..start).next_back() {
            cursor = cursor.max(before_end);
        }
        let mut visited: u64 = 0;
        for (&a, &b) in self.spans.range(start..end) {
            visited += 1;
            if self.steps.saturating_add(visited) > MAX_CARVE_STEPS {
                return Err(err(format!(
                    "minidump: carving exceeded its work budget of {MAX_CARVE_STEPS} interval steps"
                )));
            }
            if a > cursor {
                result.push((cursor, a));
            }
            cursor = cursor.max(b);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            result.push((cursor, end));
        }
        self.charge(visited)?;
        Ok(result)
    }

    fn insert(&mut self, a: u64, b: u64) -> Result<()> {
        if a >= b {
            return Ok(());
        }
        let mut lo: u64 = a;
        let mut hi: u64 = b;
        if let Some((&before_start, &before_end)) = self.spans.range(..a).next_back()
            && before_end >= a
        {
            lo = before_start;
            hi = hi.max(before_end);
        }
        let absorbed: Vec<u64> = self.spans.range(lo..=b).map(|(&start, _)| start).collect();
        self.charge(1 + absorbed.len() as u64)?;
        for start in absorbed {
            if let Some(end) = self.spans.remove(&start) {
                hi = hi.max(end);
            }
        }
        self.spans.insert(lo, hi);
        Ok(())
    }
}

fn classify_gaps(
    gaps: &[(u64, u64)],
    truncated: &[(u64, u64)],
    base: u64,
) -> (Vec<AbsentRange>, u64) {
    let mut absent: Vec<AbsentRange> = Vec::new();
    let mut truncated_bytes: u64 = 0;
    let mut next: usize = 0;
    for &(gap_start, gap_end) in gaps {
        while next < truncated.len() && truncated[next].1 <= gap_start {
            next += 1;
        }
        let mut cursor: u64 = gap_start;
        let mut index: usize = next;
        while index < truncated.len() && truncated[index].0 < gap_end {
            let lo: u64 = truncated[index].0.max(gap_start);
            let hi: u64 = truncated[index].1.min(gap_end);
            if lo > cursor {
                absent.push(absent_range(
                    base,
                    cursor,
                    lo,
                    AbsentReason::NotPresentInDump,
                ));
            }
            truncated_bytes += hi - lo;
            absent.push(absent_range(
                base,
                lo,
                hi,
                AbsentReason::TruncatedDescriptor,
            ));
            cursor = hi;
            if truncated[index].1 > gap_end {
                break;
            }
            index += 1;
        }
        if cursor < gap_end {
            absent.push(absent_range(
                base,
                cursor,
                gap_end,
                AbsentReason::NotPresentInDump,
            ));
        }
    }
    (absent, truncated_bytes)
}

const fn absent_range(base: u64, start: u64, end: u64, reason: AbsentReason) -> AbsentRange {
    AbsentRange {
        start_va: base + start,
        end_va: base + end,
        reason,
    }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod insert_tests {
    use super::{CoverSet, MAX_CARVE_STEPS, carve_module, merged};
    use crate::containers::minidump::{
        MemorySource, MinidumpFile, MinidumpMemoryRegion, MinidumpModule, ProcessorArch,
    };

    #[test]
    fn a_cover_set_insert_matches_merging_the_whole_list() {
        let mut cover: CoverSet = CoverSet::default();
        let mut all: Vec<(u64, u64)> = Vec::new();
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..2_000 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let start: u64 = (seed >> 33) % 100_000;
            let len: u64 = (seed >> 13) % 700;
            cover.insert(start, start + len).expect("within budget");
            if len > 0 {
                all.push((start, start + len));
            }
            let spans: Vec<(u64, u64)> = cover.spans.iter().map(|(&a, &b)| (a, b)).collect();
            assert_eq!(spans, merged(all.clone()));
        }
    }

    fn module(size: u32) -> MinidumpModule {
        MinidumpModule {
            base_of_image: 0x1000_0000,
            size_of_image: size,
            checksum: 0,
            timestamp: 0,
            name: "probe.dll".to_owned(),
            cv_record: None,
        }
    }

    fn dump_with(regions: Vec<MinidumpMemoryRegion>, size: u32) -> MinidumpFile {
        MinidumpFile {
            version: 0xA793,
            arch: ProcessorArch::Amd64,
            pointer_width: 8,
            stream_directory_rva: 0,
            number_of_streams: 0,
            streams: Vec::new(),
            modules: vec![module(size)],
            memory_regions: regions,
            notes: Vec::new(),
        }
    }

    fn region(offset: u64, len: u64, available: u64) -> MinidumpMemoryRegion {
        MinidumpMemoryRegion {
            start_va: 0x1000_0000 + offset,
            data_size: len,
            file_offset: 0,
            file_available: available,
            source: MemorySource::Memory64List,
        }
    }

    #[test]
    fn many_disjoint_regions_in_descending_order_carve_in_near_linear_work() {
        let count: u64 = 200_000;
        let size: u32 = 2 * 200_000;
        let regions: Vec<MinidumpMemoryRegion> = (0..count)
            .rev()
            .map(|index: u64| region(2 * index, 1, 1))
            .collect();
        let file: MinidumpFile = dump_with(regions, size);
        let dump: Vec<u8> = vec![0x5A; 16];

        let carved = carve_module(&file, &dump, &file.modules[0], u64::from(size))
            .expect("the carve stays within its work budget");

        assert_eq!(carved.coverage.covered_bytes, count);
        assert_eq!(carved.absent_ranges.len() as u64, count);
    }

    #[test]
    fn regions_rescanning_many_gaps_stop_at_the_work_budget() {
        let islands: u64 = 100_000;
        let size: u32 = 2 * 100_000;
        let mut regions: Vec<MinidumpMemoryRegion> = (0..islands)
            .map(|index: u64| region(2 * index, 1, 1))
            .collect();
        regions.extend((0..100_000).map(|_| region(0, u64::from(size), 0)));
        let file: MinidumpFile = dump_with(regions, size);
        let dump: Vec<u8> = vec![0x5A; 16];

        let refused = carve_module(&file, &dump, &file.modules[0], u64::from(size))
            .expect_err("rescanning 100,000 gaps 100,000 times exceeds the budget");

        assert!(
            refused.to_string().contains(&MAX_CARVE_STEPS.to_string()),
            "the refusal names its budget: {refused}"
        );
    }
}
