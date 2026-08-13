use disrobe_bytes::ByteReadError;
use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_section};
use crate::error::{Error, Result};
use crate::native::{NativeFormat, detect_native_format};

mod coff;
mod elf;
mod macho;
mod pe;

pub const BYTE_COVERAGE_SCHEMA: &str = "disrobe.byte-coverage/v1";

const MAX_COVERAGE_REGIONS: usize = 65_536;
const MAX_OVERLAP_RECORDS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegionClass {
    Header,
    Table,
    Code,
    Data,
    Padding,
    Signature,
    Debug,
    Alignment,
    Unclaimed,
}

impl RegionClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Table => "table",
            Self::Code => "code",
            Self::Data => "data",
            Self::Padding => "padding",
            Self::Signature => "signature",
            Self::Debug => "debug",
            Self::Alignment => "alignment",
            Self::Unclaimed => "unclaimed",
        }
    }

    #[must_use]
    pub const fn is_claimed(self) -> bool {
        !matches!(self, Self::Alignment | Self::Unclaimed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRegion {
    pub start: u64,
    pub end: u64,
    pub class: RegionClass,
    pub claimant: Option<String>,
}

impl CoverageRegion {
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageOverlap {
    pub start: u64,
    pub end: u64,
    pub first: String,
    pub second: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnbackedReason {
    NoFileOffset,
    NoFileBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbackedClaim {
    pub claimant: String,
    pub declared_size: u64,
    pub reason: UnbackedReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncatedClaim {
    pub claimant: String,
    pub start: u64,
    pub declared_end: u64,
    pub present_end: u64,
    pub missing_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteCoverage {
    pub schema: String,
    pub format: NativeFormat,
    pub file_len: u64,
    pub claimed_bytes: u64,
    pub slack_bytes: u64,
    pub unclaimed_bytes: u64,
    pub truncated_bytes: u64,
    pub coverage_ratio: f64,
    pub complete: bool,
    pub overlap_detected: bool,
    pub regions: Vec<CoverageRegion>,
    pub overlaps: Vec<CoverageOverlap>,
    pub unbacked: Vec<UnbackedClaim>,
    pub truncated: Vec<TruncatedClaim>,
}

impl ByteCoverage {
    #[must_use]
    pub fn unclaimed_ranges(&self) -> Vec<&CoverageRegion> {
        self.regions
            .iter()
            .filter(|region: &&CoverageRegion| region.class == RegionClass::Unclaimed)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Claim {
    start: u64,
    end: u64,
    class: RegionClass,
    claimant: String,
}

#[derive(Debug)]
pub(crate) struct ClaimSet<'data> {
    bytes: &'data [u8],
    file_len: u64,
    claims: Vec<Claim>,
    unbacked: Vec<UnbackedClaim>,
    truncated: Vec<TruncatedClaim>,
}

impl<'data> ClaimSet<'data> {
    pub(crate) fn new(bytes: &'data [u8]) -> Result<Self> {
        let file_len: u64 = u64::try_from(bytes.len())
            .map_err(|_error: std::num::TryFromIntError| coverage_error("file length overflows"))?;
        Ok(Self {
            bytes,
            file_len,
            claims: Vec::new(),
            unbacked: Vec::new(),
            truncated: Vec::new(),
        })
    }

    pub(crate) const fn file_len(&self) -> u64 {
        self.file_len
    }

    pub(crate) fn claim(
        &mut self,
        start: u64,
        size: u64,
        class: RegionClass,
        claimant: impl Into<String>,
    ) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let claimant: String = claimant.into();
        let end: u64 = start.checked_add(size).ok_or_else(|| {
            coverage_error(format!(
                "claim `{claimant}` at {start} overflows the offset space"
            ))
        })?;
        if end > self.file_len {
            return Err(coverage_error(format!(
                "claim `{claimant}` spans {start}..{end}, past the {} byte input",
                self.file_len
            )));
        }
        self.record(Claim {
            start,
            end,
            class,
            claimant,
        })
    }

    pub(crate) fn claim_payload(
        &mut self,
        start: u64,
        size: u64,
        class: RegionClass,
        claimant: impl Into<String>,
    ) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let claimant: String = claimant.into();
        let declared_end: u64 = start.checked_add(size).ok_or_else(|| {
            coverage_error(format!(
                "payload `{claimant}` at {start} overflows the offset space"
            ))
        })?;
        let present_end: u64 = declared_end.min(self.file_len).max(start);
        let missing_bytes: u64 = declared_end.saturating_sub(present_end);

        if missing_bytes > 0 {
            self.truncated.push(TruncatedClaim {
                claimant: claimant.clone(),
                start,
                declared_end,
                present_end,
                missing_bytes,
            });
        }
        if present_end <= start {
            return Ok(());
        }
        self.record(Claim {
            start,
            end: present_end,
            class,
            claimant,
        })
    }

    pub(crate) fn unbacked(
        &mut self,
        claimant: impl Into<String>,
        declared_size: u64,
        reason: UnbackedReason,
    ) {
        self.unbacked.push(UnbackedClaim {
            claimant: claimant.into(),
            declared_size,
            reason,
        });
    }

    fn record(&mut self, claim: Claim) -> Result<()> {
        if self.claims.len() >= MAX_COVERAGE_REGIONS {
            return Err(coverage_error(format!(
                "input declares more than {MAX_COVERAGE_REGIONS} claimed ranges"
            )));
        }
        self.claims.push(claim);
        Ok(())
    }

    pub(crate) fn finish(mut self, format: NativeFormat) -> Result<ByteCoverage> {
        self.claims.sort_by(|left: &Claim, right: &Claim| {
            left.start
                .cmp(&right.start)
                .then(left.end.cmp(&right.end))
                .then(left.claimant.cmp(&right.claimant))
        });

        let overlaps: Vec<CoverageOverlap> = detect_overlaps(&self.claims)?;
        let regions: Vec<CoverageRegion> = build_regions(self.bytes, self.file_len, &self.claims)?;

        let mut claimed_bytes: u64 = 0;
        let mut slack_bytes: u64 = 0;
        let mut unclaimed_bytes: u64 = 0;
        for region in &regions {
            let length: u64 = region.len();
            if region.class.is_claimed() {
                claimed_bytes = claimed_bytes.saturating_add(length);
            } else if region.class == RegionClass::Alignment {
                slack_bytes = slack_bytes.saturating_add(length);
            } else {
                unclaimed_bytes = unclaimed_bytes.saturating_add(length);
            }
        }

        let total: u64 = claimed_bytes
            .checked_add(slack_bytes)
            .and_then(|value: u64| value.checked_add(unclaimed_bytes))
            .ok_or_else(|| coverage_error("coverage totals overflow"))?;
        if total != self.file_len {
            return Err(coverage_error(format!(
                "coverage totals {total} do not account for the {} byte input",
                self.file_len
            )));
        }

        self.truncated
            .sort_by(|left: &TruncatedClaim, right: &TruncatedClaim| {
                left.start
                    .cmp(&right.start)
                    .then(left.claimant.cmp(&right.claimant))
            });
        self.unbacked
            .sort_by(|left: &UnbackedClaim, right: &UnbackedClaim| {
                left.claimant
                    .cmp(&right.claimant)
                    .then(left.declared_size.cmp(&right.declared_size))
            });

        let truncated_bytes: u64 = self
            .truncated
            .iter()
            .fold(0u64, |total: u64, entry: &TruncatedClaim| {
                total.saturating_add(entry.missing_bytes)
            });
        let overlap_detected: bool = !overlaps.is_empty();
        let coverage_ratio: f64 = claimed_bytes as f64 / self.file_len as f64;

        dbg_kv("coverage.format", || format.label().to_owned());
        dbg_kv("coverage.regions", || regions.len().to_string());
        dbg_kv("coverage.claimed", || claimed_bytes.to_string());
        dbg_kv("coverage.slack", || slack_bytes.to_string());
        dbg_kv("coverage.unclaimed", || unclaimed_bytes.to_string());

        Ok(ByteCoverage {
            schema: BYTE_COVERAGE_SCHEMA.to_owned(),
            format,
            file_len: self.file_len,
            claimed_bytes,
            slack_bytes,
            unclaimed_bytes,
            truncated_bytes,
            coverage_ratio,
            complete: unclaimed_bytes == 0 && !overlap_detected,
            overlap_detected,
            regions,
            overlaps,
            unbacked: self.unbacked,
            truncated: self.truncated,
        })
    }
}

fn detect_overlaps(claims: &[Claim]) -> Result<Vec<CoverageOverlap>> {
    let mut overlaps: Vec<CoverageOverlap> = Vec::new();
    let mut active: Vec<&Claim> = Vec::new();

    for claim in claims {
        active.retain(|candidate: &&Claim| candidate.end > claim.start);
        for candidate in &active {
            let start: u64 = candidate.start.max(claim.start);
            let end: u64 = candidate.end.min(claim.end);
            if start >= end {
                continue;
            }
            if overlaps.len() >= MAX_OVERLAP_RECORDS {
                return Err(coverage_error(format!(
                    "input declares more than {MAX_OVERLAP_RECORDS} claim overlaps"
                )));
            }
            overlaps.push(CoverageOverlap {
                start,
                end,
                first: candidate.claimant.clone(),
                second: claim.claimant.clone(),
            });
        }
        active.push(claim);
    }

    Ok(overlaps)
}

fn build_regions(bytes: &[u8], file_len: u64, claims: &[Claim]) -> Result<Vec<CoverageRegion>> {
    let mut regions: Vec<CoverageRegion> = Vec::new();
    let mut cursor: u64 = 0;

    for claim in claims {
        if claim.start > cursor {
            push_gap(bytes, &mut regions, cursor, claim.start, false)?;
            cursor = claim.start;
        }
        if claim.end <= cursor {
            continue;
        }
        push_region(
            &mut regions,
            CoverageRegion {
                start: cursor,
                end: claim.end,
                class: claim.class,
                claimant: Some(claim.claimant.clone()),
            },
        )?;
        cursor = claim.end;
    }

    if cursor < file_len {
        push_gap(bytes, &mut regions, cursor, file_len, true)?;
    }

    Ok(regions)
}

fn push_gap(
    bytes: &[u8],
    regions: &mut Vec<CoverageRegion>,
    start: u64,
    end: u64,
    trailing: bool,
) -> Result<()> {
    if end <= start {
        return Ok(());
    }
    let class: RegionClass = if trailing || !range_is_zero(bytes, start, end)? {
        RegionClass::Unclaimed
    } else {
        RegionClass::Alignment
    };
    push_region(
        regions,
        CoverageRegion {
            start,
            end,
            class,
            claimant: None,
        },
    )
}

fn push_region(regions: &mut Vec<CoverageRegion>, region: CoverageRegion) -> Result<()> {
    if regions.len() >= MAX_COVERAGE_REGIONS {
        return Err(coverage_error(format!(
            "input produces more than {MAX_COVERAGE_REGIONS} coverage regions"
        )));
    }
    regions.push(region);
    Ok(())
}

fn range_is_zero(bytes: &[u8], start: u64, end: u64) -> Result<bool> {
    let start_index: usize = usize::try_from(start)
        .map_err(|_error: std::num::TryFromIntError| coverage_error("gap start overflows usize"))?;
    let end_index: usize = usize::try_from(end)
        .map_err(|_error: std::num::TryFromIntError| coverage_error("gap end overflows usize"))?;
    let slice: &[u8] = bytes
        .get(start_index..end_index)
        .ok_or_else(|| coverage_error("gap range falls outside the input"))?;

    Ok(slice.iter().all(|value: &u8| *value == 0))
}

pub(crate) fn coverage_error(message: impl Into<String>) -> Error {
    Error::Coverage(message.into())
}

pub(crate) fn read_error(subject: &str, error: ByteReadError) -> Error {
    coverage_error(format!("{subject} is truncated: {error}"))
}

pub(crate) fn unsupported(format: NativeFormat, detail: impl Into<String>) -> Error {
    Error::CoverageUnsupported {
        format: format.label(),
        detail: detail.into(),
    }
}

pub fn file_byte_coverage(bytes: &[u8]) -> Result<ByteCoverage> {
    dbg_section("byte-coverage");
    if bytes.is_empty() {
        return Err(coverage_error(
            "input is empty, so it has no byte to account for",
        ));
    }

    if crate::ne::is_ne(bytes) {
        return Err(Error::CoverageUnsupported {
            format: "ne",
            detail: "the new-executable segment, resource, relocation and entry tables are not \
                     mapped to file offsets by this walk"
                .to_owned(),
        });
    }

    let format: NativeFormat = detect_native_format(bytes)?;
    dbg_kv("coverage.detected", || format.label().to_owned());

    match format {
        NativeFormat::Pe32 => pe::map_pe32(bytes),
        NativeFormat::Pe64 => pe::map_pe64(bytes),
        NativeFormat::Elf32 | NativeFormat::Elf64 => elf::map_elf(bytes, format),
        NativeFormat::MachO32 | NativeFormat::MachO64 => macho::map_thin(bytes, format),
        NativeFormat::MachOFat => macho::map_fat(bytes),
        NativeFormat::Coff => coff::map_coff(bytes),
        NativeFormat::NeWindows | NativeFormat::NeOs2 => Err(unsupported(
            format,
            "the new-executable segment, resource, relocation and entry tables are not mapped to \
             file offsets by this walk",
        )),
        NativeFormat::Wasm => Err(unsupported(
            format,
            "the WebAssembly section stream is not mapped to file offsets by this walk",
        )),
    }
}
