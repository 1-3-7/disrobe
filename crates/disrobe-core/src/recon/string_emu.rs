use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

pub const DEFAULT_STEP_LIMIT: u64 = 200_000;
pub const DEFAULT_WALL_CLOCK: Duration = Duration::from_millis(750);
pub const DEFAULT_DELTA_BYTES: u64 = 256 << 10;
pub const DEFAULT_DECODER_CALLS: u32 = 256;

pub const MAX_ARGUMENTS: usize = 64;
pub const MAX_SANDBOX_REGIONS: usize = 64;

const MIN_RUN_CHARS: usize = 4;
const MAX_RUNS: usize = 4096;
const MAX_RUN_BYTES: usize = 64 << 10;
const MAX_SEALED_SPANS: usize = 256;
const CLOCK_STRIDE: usize = 1024;
const MAX_LOG_ENTRIES: usize = 1 << 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmulationBound {
    Steps,
    WallClock,
    DeltaBytes,
    DecoderCalls,
}

impl EmulationBound {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Steps => "steps",
            Self::WallClock => "wall-clock",
            Self::DeltaBytes => "delta-bytes",
            Self::DecoderCalls => "decoder-calls",
        }
    }
}

impl std::fmt::Display for EmulationBound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmulationLimits {
    pub steps: u64,
    pub wall_clock: Duration,
    pub delta_bytes: u64,
    pub decoder_calls: u32,
}

impl Default for EmulationLimits {
    #[inline]
    fn default() -> Self {
        Self {
            steps: DEFAULT_STEP_LIMIT,
            wall_clock: DEFAULT_WALL_CLOCK,
            delta_bytes: DEFAULT_DELTA_BYTES,
            decoder_calls: DEFAULT_DECODER_CALLS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmulationBudget {
    limits: EmulationLimits,
    started: Instant,
    steps_left: u64,
    delta_bytes_left: u64,
    decoder_calls_left: u32,
    hit: Option<EmulationBound>,
}

impl EmulationBudget {
    #[inline]
    #[must_use]
    pub const fn new(limits: EmulationLimits, started: Instant) -> Self {
        Self {
            limits,
            started,
            steps_left: limits.steps,
            delta_bytes_left: limits.delta_bytes,
            decoder_calls_left: limits.decoder_calls,
            hit: None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn limits(&self) -> EmulationLimits {
        self.limits
    }

    #[inline]
    #[must_use]
    pub const fn started(&self) -> Instant {
        self.started
    }

    #[inline]
    #[must_use]
    pub const fn bound_hit(&self) -> Option<EmulationBound> {
        self.hit
    }

    #[inline]
    #[must_use]
    pub const fn steps_remaining(&self) -> u64 {
        self.steps_left
    }

    #[inline]
    #[must_use]
    pub const fn delta_bytes_remaining(&self) -> u64 {
        self.delta_bytes_left
    }

    #[inline]
    #[must_use]
    pub const fn decoder_calls_remaining(&self) -> u32 {
        self.decoder_calls_left
    }

    fn trip(&mut self, bound: EmulationBound) -> EmulationBound {
        let first: EmulationBound = self.hit.unwrap_or(bound);
        self.hit = Some(first);
        first
    }

    const fn guard(&self) -> Result<(), EmulationBound> {
        match self.hit {
            Some(bound) => Err(bound),
            None => Ok(()),
        }
    }

    pub fn check_clock(&mut self, now: Instant) -> Result<(), EmulationBound> {
        self.guard()?;
        if now.saturating_duration_since(self.started) > self.limits.wall_clock {
            return Err(self.trip(EmulationBound::WallClock));
        }
        Ok(())
    }

    pub fn tick(&mut self, steps: u64, now: Instant) -> Result<(), EmulationBound> {
        self.check_clock(now)?;
        let Some(left): Option<u64> = self.steps_left.checked_sub(steps) else {
            self.steps_left = 0;
            return Err(self.trip(EmulationBound::Steps));
        };
        self.steps_left = left;
        Ok(())
    }

    pub fn enter_decoder(&mut self) -> Result<(), EmulationBound> {
        self.guard()?;
        let Some(left): Option<u32> = self.decoder_calls_left.checked_sub(1) else {
            return Err(self.trip(EmulationBound::DecoderCalls));
        };
        self.decoder_calls_left = left;
        Ok(())
    }

    pub fn charge_delta(&mut self, bytes: u64) -> Result<(), EmulationBound> {
        self.guard()?;
        let Some(left): Option<u64> = self.delta_bytes_left.checked_sub(bytes) else {
            self.delta_bytes_left = 0;
            return Err(self.trip(EmulationBound::DeltaBytes));
        };
        self.delta_bytes_left = left;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
    Bytes,
}

impl StringEncoding {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf8 => "utf-8",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::Utf32Le => "utf-32le",
            Self::Utf32Be => "utf-32be",
            Self::Bytes => "bytes",
        }
    }

    #[inline]
    #[must_use]
    pub const fn code_unit_bytes(self) -> usize {
        match self {
            Self::Ascii | Self::Utf8 | Self::Bytes => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
            Self::Utf32Le | Self::Utf32Be => 4,
        }
    }
}

impl std::fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedString {
    pub address: u64,
    pub encoding: StringEncoding,
    pub bytes: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl DecodedString {
    #[inline]
    #[must_use]
    pub const fn span(&self) -> u64 {
        self.bytes.len() as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    pub min_chars: usize,
    pub max_runs: usize,
    pub max_run_bytes: usize,
}

impl Default for RunLimits {
    #[inline]
    fn default() -> Self {
        Self {
            min_chars: MIN_RUN_CHARS,
            max_runs: MAX_RUNS,
            max_run_bytes: MAX_RUN_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxError {
    RegionOverflow { base: u64, len: u64 },
    TooManyRegions { limit: usize },
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionOverflow { base, len } => write!(
                f,
                "DR-RECON-EMU-0001: sandbox region at 0x{base:016x} of {len} bytes leaves the address space"
            ),
            Self::TooManyRegions { limit } => write!(
                f,
                "DR-RECON-EMU-0002: sandbox refuses more than {limit} mapped regions"
            ),
        }
    }
}

impl std::error::Error for SandboxError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxWindow {
    regions: Vec<(u64, u64)>,
}

impl SandboxWindow {
    pub fn allow(&mut self, base: u64, len: u64) -> Result<(), SandboxError> {
        if self.regions.len() >= MAX_SANDBOX_REGIONS {
            return Err(SandboxError::TooManyRegions {
                limit: MAX_SANDBOX_REGIONS,
            });
        }
        if len == 0 {
            return Ok(());
        }
        let last: u64 = base
            .checked_add(len - 1)
            .ok_or(SandboxError::RegionOverflow { base, len })?;
        self.regions.push((base, last));
        self.regions.sort_unstable();
        Ok(())
    }

    #[inline]
    #[must_use]
    pub fn contains(&self, address: u64) -> bool {
        self.regions
            .iter()
            .any(|&(start, last): &(u64, u64)| address >= start && address <= last)
    }

    #[inline]
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    #[inline]
    #[must_use]
    pub fn mapped_bytes(&self) -> u128 {
        self.regions
            .iter()
            .map(|&(start, last): &(u64, u64)| u128::from(last - start) + 1)
            .sum()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryDelta {
    pub strings: Vec<DecodedString>,
    pub bytes_recorded: u64,
    pub writes_outside_sandbox: u64,
    pub bound: Option<EmulationBound>,
}

#[derive(Debug, Clone, Copy)]
struct SealedSpan {
    start: u64,
    end: u64,
    rewritten: u64,
}

pub fn harvest_memory_delta(
    log: &[(u64, u8)],
    window: &SandboxWindow,
    budget: &mut EmulationBudget,
    now: Instant,
) -> MemoryDelta {
    let limits: RunLimits = RunLimits::default();
    let mut delta: MemoryDelta = MemoryDelta::default();
    if let Err(bound) = budget.check_clock(now) {
        delta.bound = Some(bound);
        return delta;
    }

    let mut shadow: BTreeMap<u64, u8> = BTreeMap::new();
    let mut sealed: Vec<SealedSpan> = Vec::new();
    let mut harvested: Vec<DecodedString> = Vec::new();

    for (index, &(address, value)) in log.iter().take(MAX_LOG_ENTRIES).enumerate() {
        if index % CLOCK_STRIDE == 0
            && let Err(bound) = budget.check_clock(now)
        {
            delta.bound = Some(bound);
            break;
        }
        if !window.contains(address) {
            delta.writes_outside_sandbox = delta.writes_outside_sandbox.saturating_add(1);
            continue;
        }
        let changed: bool = shadow.get(&address).is_some_and(|&old: &u8| old != value);
        if changed && !touch_sealed(&mut sealed, address) {
            seal_run(&shadow, address, &limits, &mut sealed, &mut harvested);
        }
        if !shadow.contains_key(&address) {
            if let Err(bound) = budget.charge_delta(1) {
                delta.bound = Some(bound);
                break;
            }
            delta.bytes_recorded = delta.bytes_recorded.saturating_add(1);
        }
        shadow.insert(address, value);
    }

    for (base, bytes) in contiguous_segments(&shadow, &limits) {
        if harvested.len() >= limits.max_runs {
            break;
        }
        harvested.extend(extract_region(base, &bytes, &limits));
    }

    delta.strings = finalize(harvested, &limits);
    delta
}

fn touch_sealed(sealed: &mut Vec<SealedSpan>, address: u64) -> bool {
    let Some(index): Option<usize> = sealed
        .iter()
        .position(|span: &SealedSpan| address >= span.start && address < span.end)
    else {
        return false;
    };
    let span: &mut SealedSpan = &mut sealed[index];
    span.rewritten = span.rewritten.saturating_add(1);
    if span.rewritten >= span.end.saturating_sub(span.start) {
        sealed.remove(index);
    }
    true
}

fn seal_run(
    shadow: &BTreeMap<u64, u8>,
    address: u64,
    limits: &RunLimits,
    sealed: &mut Vec<SealedSpan>,
    out: &mut Vec<DecodedString>,
) {
    let Some((start, bytes)): Option<(u64, Vec<u8>)> = run_around(shadow, address, limits) else {
        return;
    };
    let end: u64 = start.saturating_add(bytes.len() as u64);
    if sealed.len() >= MAX_SEALED_SPANS {
        sealed.remove(0);
    }
    sealed.push(SealedSpan {
        start,
        end,
        rewritten: 0,
    });
    if out.len() < limits.max_runs {
        out.extend(extract_region(start, &bytes, limits));
    }
}

fn run_around(
    shadow: &BTreeMap<u64, u8>,
    address: u64,
    limits: &RunLimits,
) -> Option<(u64, Vec<u8>)> {
    shadow.get(&address)?;
    let mut start: u64 = address;
    let mut back: usize = 0;
    while back < limits.max_run_bytes {
        let Some(previous): Option<u64> = start.checked_sub(1) else {
            break;
        };
        if !shadow.contains_key(&previous) {
            break;
        }
        start = previous;
        back += 1;
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut cursor: u64 = start;
    while bytes.len() < limits.max_run_bytes {
        let Some(&byte): Option<&u8> = shadow.get(&cursor) else {
            break;
        };
        bytes.push(byte);
        let Some(next): Option<u64> = cursor.checked_add(1) else {
            break;
        };
        cursor = next;
    }
    if bytes.is_empty() {
        return None;
    }
    Some((start, bytes))
}

fn contiguous_segments(shadow: &BTreeMap<u64, u8>, limits: &RunLimits) -> Vec<(u64, Vec<u8>)> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut base: Option<u64> = None;
    let mut previous: Option<u64> = None;
    let mut current: Vec<u8> = Vec::new();
    for (&address, &byte) in shadow {
        let adjacent: bool = previous
            .is_some_and(|last: u64| last.checked_add(1).is_some_and(|next: u64| next == address));
        if !adjacent || current.len() >= limits.max_run_bytes {
            if let Some(start) = base
                && !current.is_empty()
            {
                out.push((start, std::mem::take(&mut current)));
            }
            current.clear();
            base = Some(address);
        }
        current.push(byte);
        previous = Some(address);
        if out.len() >= limits.max_runs {
            return out;
        }
    }
    if let Some(start) = base
        && !current.is_empty()
    {
        out.push((start, current));
    }
    out
}

fn extract_region(base: u64, bytes: &[u8], limits: &RunLimits) -> Vec<DecodedString> {
    let mut found: Vec<DecodedString> = Vec::new();
    for encoding in [
        StringEncoding::Utf8,
        StringEncoding::Utf16Le,
        StringEncoding::Utf16Be,
        StringEncoding::Utf32Le,
        StringEncoding::Utf32Be,
    ] {
        found.extend(text_runs(bytes, base, encoding, limits));
    }
    let mut merged: Vec<DecodedString> = merge_runs(found, limits);
    let covered: usize = merged
        .iter()
        .map(|run: &DecodedString| run.bytes.len())
        .sum();
    if covered < bytes.len() && bytes.len() >= limits.min_chars {
        merged.push(DecodedString {
            address: base,
            encoding: StringEncoding::Bytes,
            bytes: bytes.to_vec(),
            text: None,
        });
    }
    merged
}

#[must_use]
pub fn text_runs(
    bytes: &[u8],
    base: u64,
    encoding: StringEncoding,
    limits: &RunLimits,
) -> Vec<DecodedString> {
    let raw: Vec<DecodedString> = match encoding {
        StringEncoding::Bytes => {
            if bytes.len() < limits.min_chars {
                Vec::new()
            } else {
                vec![DecodedString {
                    address: base,
                    encoding: StringEncoding::Bytes,
                    bytes: bytes[..bytes.len().min(limits.max_run_bytes)].to_vec(),
                    text: None,
                }]
            }
        }
        StringEncoding::Ascii | StringEncoding::Utf8 => {
            unit_runs_narrow(bytes, base, encoding, limits)
        }
        StringEncoding::Utf16Le
        | StringEncoding::Utf16Be
        | StringEncoding::Utf32Le
        | StringEncoding::Utf32Be => unit_runs_wide(bytes, base, encoding, limits),
    };
    merge_runs(raw, limits)
}

fn unit_runs_narrow(
    bytes: &[u8],
    base: u64,
    encoding: StringEncoding,
    limits: &RunLimits,
) -> Vec<DecodedString> {
    let mut out: Vec<DecodedString> = Vec::new();
    let allow_wide_scalars: bool = matches!(encoding, StringEncoding::Utf8);
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        if out.len() >= limits.max_runs {
            return out;
        }
        let rest: &[u8] = &bytes[cursor..];
        let valid_len: usize = match std::str::from_utf8(rest) {
            Ok(_) => rest.len(),
            Err(error) => error.valid_up_to(),
        };
        if valid_len == 0 {
            cursor += 1;
            continue;
        }
        let text: &str = std::str::from_utf8(&rest[..valid_len]).unwrap_or("");
        collect_narrow_runs(text, base, cursor, allow_wide_scalars, limits, &mut out);
        cursor += valid_len.max(1);
    }
    out
}

fn collect_narrow_runs(
    text: &str,
    base: u64,
    origin: usize,
    allow_wide_scalars: bool,
    limits: &RunLimits,
    out: &mut Vec<DecodedString>,
) {
    let mut run_start: Option<usize> = None;
    let mut run_end: usize = 0;
    for (offset, scalar) in text.char_indices() {
        let keep: bool = if allow_wide_scalars {
            is_text_scalar(scalar)
        } else {
            is_printable_ascii_scalar(scalar)
        };
        if keep {
            if run_start.is_none() {
                run_start = Some(offset);
            }
            run_end = offset + scalar.len_utf8();
            if run_end.saturating_sub(run_start.unwrap_or(offset)) >= limits.max_run_bytes {
                push_narrow_run(text, base, origin, run_start, run_end, limits, out);
                run_start = None;
            }
        } else if run_start.is_some() {
            push_narrow_run(text, base, origin, run_start, run_end, limits, out);
            run_start = None;
        }
    }
    push_narrow_run(text, base, origin, run_start, run_end, limits, out);
}

fn push_narrow_run(
    text: &str,
    base: u64,
    origin: usize,
    run_start: Option<usize>,
    run_end: usize,
    limits: &RunLimits,
    out: &mut Vec<DecodedString>,
) {
    let Some(start): Option<usize> = run_start else {
        return;
    };
    let Some(slice): Option<&str> = text.get(start..run_end) else {
        return;
    };
    if slice.chars().count() < limits.min_chars || out.len() >= limits.max_runs {
        return;
    }
    let all_ascii: bool = slice.is_ascii();
    out.push(DecodedString {
        address: base.wrapping_add((origin + start) as u64),
        encoding: if all_ascii {
            StringEncoding::Ascii
        } else {
            StringEncoding::Utf8
        },
        bytes: slice.as_bytes().to_vec(),
        text: Some(slice.to_owned()),
    });
}

fn unit_runs_wide(
    bytes: &[u8],
    base: u64,
    encoding: StringEncoding,
    limits: &RunLimits,
) -> Vec<DecodedString> {
    let unit: usize = encoding.code_unit_bytes();
    let mut out: Vec<DecodedString> = Vec::new();
    for alignment in 0..unit {
        if alignment >= bytes.len() {
            break;
        }
        let mut reader: ByteReader<'_> = ByteReader::new(bytes);
        if reader.seek(alignment).is_err() {
            continue;
        }
        let mut run_start: Option<usize> = None;
        let mut chars: String = String::new();
        while reader.remaining() >= unit {
            if out.len() >= limits.max_runs {
                return out;
            }
            let position: usize = reader.position();
            let Some(scalar): Option<char> = read_wide_unit(&mut reader, encoding) else {
                break;
            };
            if is_printable_ascii_scalar(scalar) && chars.len() * unit < limits.max_run_bytes {
                if run_start.is_none() {
                    run_start = Some(position);
                }
                chars.push(scalar);
            } else {
                push_wide_run(base, encoding, run_start, &chars, limits, out.as_mut());
                run_start = None;
                chars.clear();
            }
        }
        push_wide_run(base, encoding, run_start, &chars, limits, out.as_mut());
    }
    out
}

fn read_wide_unit(reader: &mut ByteReader<'_>, encoding: StringEncoding) -> Option<char> {
    let raw: u32 = match encoding {
        StringEncoding::Utf16Le => u32::from(reader.read_u16_le().ok()?),
        StringEncoding::Utf16Be => u32::from(reader.read_u16_be().ok()?),
        StringEncoding::Utf32Le => reader.read_u32_le().ok()?,
        StringEncoding::Utf32Be => reader.read_u32_be().ok()?,
        StringEncoding::Ascii | StringEncoding::Utf8 | StringEncoding::Bytes => return None,
    };
    char::from_u32(raw)
}

fn push_wide_run(
    base: u64,
    encoding: StringEncoding,
    run_start: Option<usize>,
    chars: &str,
    limits: &RunLimits,
    out: &mut Vec<DecodedString>,
) {
    let Some(start): Option<usize> = run_start else {
        return;
    };
    if chars.chars().count() < limits.min_chars || out.len() >= limits.max_runs {
        return;
    }
    let unit: usize = encoding.code_unit_bytes();
    let mut raw: Vec<u8> = Vec::with_capacity(chars.len() * unit);
    for scalar in chars.chars() {
        let value: u32 = scalar as u32;
        match encoding {
            StringEncoding::Utf16Le => raw.extend_from_slice(&(value as u16).to_le_bytes()),
            StringEncoding::Utf16Be => raw.extend_from_slice(&(value as u16).to_be_bytes()),
            StringEncoding::Utf32Le => raw.extend_from_slice(&value.to_le_bytes()),
            StringEncoding::Utf32Be => raw.extend_from_slice(&value.to_be_bytes()),
            StringEncoding::Ascii | StringEncoding::Utf8 | StringEncoding::Bytes => return,
        }
    }
    out.push(DecodedString {
        address: base.wrapping_add(start as u64),
        encoding,
        bytes: raw,
        text: Some(chars.to_owned()),
    });
}

fn merge_runs(mut runs: Vec<DecodedString>, limits: &RunLimits) -> Vec<DecodedString> {
    runs.sort_by(|a: &DecodedString, b: &DecodedString| {
        a.address
            .cmp(&b.address)
            .then(b.span().cmp(&a.span()))
            .then(a.encoding.cmp(&b.encoding))
            .then(a.bytes.cmp(&b.bytes))
    });
    let mut kept: Vec<DecodedString> = Vec::new();
    for run in runs {
        if kept.len() >= limits.max_runs {
            break;
        }
        let Some(previous): Option<&DecodedString> = kept.last() else {
            kept.push(run);
            continue;
        };
        if !overlaps(previous, &run) {
            kept.push(run);
            continue;
        }
        let displaces: bool = run.span() > previous.span()
            && kept
                .len()
                .checked_sub(2)
                .is_none_or(|before: usize| !overlaps(&kept[before], &run));
        if displaces {
            kept.pop();
            kept.push(run);
        }
    }
    kept
}

const fn overlaps(left: &DecodedString, right: &DecodedString) -> bool {
    let left_end: u64 = left.address.saturating_add(left.span());
    let right_end: u64 = right.address.saturating_add(right.span());
    left.address < right_end && right.address < left_end
}

fn finalize(mut runs: Vec<DecodedString>, limits: &RunLimits) -> Vec<DecodedString> {
    runs.sort_by(|a: &DecodedString, b: &DecodedString| {
        a.address
            .cmp(&b.address)
            .then(b.span().cmp(&a.span()))
            .then(a.encoding.cmp(&b.encoding))
            .then(a.bytes.cmp(&b.bytes))
    });
    runs.dedup_by(|a: &mut DecodedString, b: &mut DecodedString| {
        a.address == b.address && a.bytes == b.bytes
    });
    runs.truncate(limits.max_runs);
    runs
}

#[inline]
const fn is_printable_ascii_scalar(scalar: char) -> bool {
    matches!(scalar, ' '..='~')
}

#[inline]
const fn is_text_scalar(scalar: char) -> bool {
    matches!(scalar, ' '..='~' | '\u{a0}'..='\u{d7ff}' | '\u{e000}'..='\u{fffc}')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallConvention {
    SysV64,
    Win64,
    Aapcs64,
    Cdecl32,
    Stdcall32,
    Fastcall32,
    Thiscall32,
}

impl CallConvention {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SysV64 => "sysv64",
            Self::Win64 => "win64",
            Self::Aapcs64 => "aapcs64",
            Self::Cdecl32 => "cdecl32",
            Self::Stdcall32 => "stdcall32",
            Self::Fastcall32 => "fastcall32",
            Self::Thiscall32 => "thiscall32",
        }
    }

    #[inline]
    #[must_use]
    pub const fn pointer_bytes(self) -> u64 {
        match self {
            Self::SysV64 | Self::Win64 | Self::Aapcs64 => 8,
            Self::Cdecl32 | Self::Stdcall32 | Self::Fastcall32 | Self::Thiscall32 => 4,
        }
    }

    #[inline]
    #[must_use]
    pub const fn register_slots(self) -> &'static [ArgumentRegister] {
        match self {
            Self::SysV64 => &[
                ArgumentRegister::Rdi,
                ArgumentRegister::Rsi,
                ArgumentRegister::Rdx,
                ArgumentRegister::Rcx,
                ArgumentRegister::R8,
                ArgumentRegister::R9,
            ],
            Self::Win64 => &[
                ArgumentRegister::Rcx,
                ArgumentRegister::Rdx,
                ArgumentRegister::R8,
                ArgumentRegister::R9,
            ],
            Self::Aapcs64 => &[
                ArgumentRegister::X0,
                ArgumentRegister::X1,
                ArgumentRegister::X2,
                ArgumentRegister::X3,
                ArgumentRegister::X4,
                ArgumentRegister::X5,
                ArgumentRegister::X6,
                ArgumentRegister::X7,
            ],
            Self::Cdecl32 | Self::Stdcall32 => &[],
            Self::Fastcall32 => &[ArgumentRegister::Ecx, ArgumentRegister::Edx],
            Self::Thiscall32 => &[ArgumentRegister::Ecx],
        }
    }

    #[inline]
    #[must_use]
    pub const fn first_stack_offset(self) -> u64 {
        match self {
            Self::SysV64 => 8,
            Self::Win64 => 0x28,
            Self::Aapcs64 => 0,
            Self::Cdecl32 | Self::Stdcall32 | Self::Fastcall32 | Self::Thiscall32 => 4,
        }
    }

    #[inline]
    #[must_use]
    pub const fn callee_cleans_stack(self) -> bool {
        matches!(self, Self::Stdcall32 | Self::Fastcall32 | Self::Thiscall32)
    }
}

impl std::fmt::Display for CallConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgumentRegister {
    Rdi,
    Rsi,
    Rdx,
    Rcx,
    R8,
    R9,
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    Ecx,
    Edx,
}

impl ArgumentRegister {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Rdi => "rdi",
            Self::Rsi => "rsi",
            Self::Rdx => "rdx",
            Self::Rcx => "rcx",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::X0 => "x0",
            Self::X1 => "x1",
            Self::X2 => "x2",
            Self::X3 => "x3",
            Self::X4 => "x4",
            Self::X5 => "x5",
            Self::X6 => "x6",
            Self::X7 => "x7",
            Self::Ecx => "ecx",
            Self::Edx => "edx",
        }
    }
}

impl std::fmt::Display for ArgumentRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArgumentSlot {
    Register(ArgumentRegister),
    Stack { offset: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArgumentError {
    UnsupportedIndex {
        convention: CallConvention,
        index: usize,
        limit: usize,
    },
    MissingRegister {
        convention: CallConvention,
        register: ArgumentRegister,
        index: usize,
    },
    StackOutOfRange {
        convention: CallConvention,
        index: usize,
        offset: u64,
        available: usize,
    },
}

impl std::fmt::Display for ArgumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedIndex {
                convention,
                index,
                limit,
            } => write!(
                f,
                "DR-RECON-EMU-0003: {convention} argument {index} exceeds the {limit}-argument ceiling"
            ),
            Self::MissingRegister {
                convention,
                register,
                index,
            } => write!(
                f,
                "DR-RECON-EMU-0004: {convention} argument {index} needs register {register}, which the call site did not capture"
            ),
            Self::StackOutOfRange {
                convention,
                index,
                offset,
                available,
            } => write!(
                f,
                "DR-RECON-EMU-0005: {convention} argument {index} sits at stack offset {offset}, past the {available}-byte captured image"
            ),
        }
    }
}

impl std::error::Error for ArgumentError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSiteState {
    registers: BTreeMap<ArgumentRegister, u64>,
    stack_pointer: u64,
    stack: Vec<u8>,
}

impl CallSiteState {
    #[must_use]
    pub const fn new(stack_pointer: u64, stack: Vec<u8>) -> Self {
        Self {
            registers: BTreeMap::new(),
            stack_pointer,
            stack,
        }
    }

    pub fn set_register(&mut self, register: ArgumentRegister, value: u64) -> &mut Self {
        self.registers.insert(register, value);
        self
    }

    #[inline]
    #[must_use]
    pub fn register(&self, register: ArgumentRegister) -> Option<u64> {
        self.registers.get(&register).copied()
    }

    #[inline]
    #[must_use]
    pub const fn stack_pointer(&self) -> u64 {
        self.stack_pointer
    }

    #[inline]
    #[must_use]
    pub const fn stack_len(&self) -> usize {
        self.stack.len()
    }
}

pub fn argument_slot(
    convention: CallConvention,
    index: usize,
) -> Result<ArgumentSlot, ArgumentError> {
    if index >= MAX_ARGUMENTS {
        return Err(ArgumentError::UnsupportedIndex {
            convention,
            index,
            limit: MAX_ARGUMENTS,
        });
    }
    let registers: &'static [ArgumentRegister] = convention.register_slots();
    if let Some(&register) = registers.get(index) {
        return Ok(ArgumentSlot::Register(register));
    }
    let stack_index: u64 = (index - registers.len()) as u64;
    let offset: u64 = stack_index
        .checked_mul(convention.pointer_bytes())
        .and_then(|scaled: u64| scaled.checked_add(convention.first_stack_offset()))
        .ok_or(ArgumentError::UnsupportedIndex {
            convention,
            index,
            limit: MAX_ARGUMENTS,
        })?;
    Ok(ArgumentSlot::Stack { offset })
}

pub fn extract_arguments(
    state: &CallSiteState,
    convention: CallConvention,
    count: usize,
) -> Result<Vec<u64>, ArgumentError> {
    if count > MAX_ARGUMENTS {
        return Err(ArgumentError::UnsupportedIndex {
            convention,
            index: count,
            limit: MAX_ARGUMENTS,
        });
    }
    let mut out: Vec<u64> = Vec::with_capacity(count);
    for index in 0..count {
        out.push(extract_argument(state, convention, index)?);
    }
    Ok(out)
}

pub fn extract_argument(
    state: &CallSiteState,
    convention: CallConvention,
    index: usize,
) -> Result<u64, ArgumentError> {
    match argument_slot(convention, index)? {
        ArgumentSlot::Register(register) => {
            state
                .register(register)
                .ok_or(ArgumentError::MissingRegister {
                    convention,
                    register,
                    index,
                })
        }
        ArgumentSlot::Stack { offset } => read_stack_word(state, convention, index, offset),
    }
}

fn read_stack_word(
    state: &CallSiteState,
    convention: CallConvention,
    index: usize,
    offset: u64,
) -> Result<u64, ArgumentError> {
    let width: u64 = convention.pointer_bytes();
    let out_of_range: ArgumentError = ArgumentError::StackOutOfRange {
        convention,
        index,
        offset,
        available: state.stack.len(),
    };
    let start: usize = usize::try_from(offset).map_err(|_| out_of_range)?;
    let span: usize = usize::try_from(width).map_err(|_| out_of_range)?;
    let mut reader: ByteReader<'_> = ByteReader::new(&state.stack);
    reader.seek(start).map_err(|_| out_of_range)?;
    if reader.remaining() < span {
        return Err(out_of_range);
    }
    match width {
        8 => reader.read_u64_le().map_err(|_| out_of_range),
        _ => reader
            .read_u32_le()
            .map(u64::from)
            .map_err(|_| out_of_range),
    }
}
