use super::{Location, MemorySummary};

#[derive(Debug, Clone, Copy)]
pub(super) struct Fields<'a> {
    pub data: &'a [u8],
    pub big_endian: bool,
}

impl<'a> Fields<'a> {
    pub(super) const fn new(data: &'a [u8], big_endian: bool) -> Self {
        Self { data, big_endian }
    }

    fn take<const N: usize>(&self, at: usize) -> Option<[u8; N]> {
        let end: usize = at.checked_add(N)?;
        let slice: &[u8] = self.data.get(at..end)?;
        let mut out: [u8; N] = [0; N];
        out.copy_from_slice(slice);
        Some(out)
    }

    pub(super) fn u16(&self, at: usize) -> Option<u16> {
        let raw: [u8; 2] = self.take(at)?;
        Some(if self.big_endian {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    }

    pub(super) fn u32(&self, at: usize) -> Option<u32> {
        let raw: [u8; 4] = self.take(at)?;
        Some(if self.big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    }

    pub(super) fn i32(&self, at: usize) -> Option<i32> {
        self.u32(at).map(u32::cast_signed)
    }

    pub(super) fn u64(&self, at: usize) -> Option<u64> {
        let raw: [u8; 8] = self.take(at)?;
        Some(if self.big_endian {
            u64::from_be_bytes(raw)
        } else {
            u64::from_le_bytes(raw)
        })
    }

    pub(super) fn word(&self, at: usize, pointer_bytes: u8) -> Option<u64> {
        if pointer_bytes == 8 {
            self.u64(at)
        } else {
            self.u32(at).map(u64::from)
        }
    }

    pub(super) fn c_string(&self, at: usize, len: usize) -> Option<String> {
        let end: usize = at.checked_add(len)?;
        let raw: &[u8] = self.data.get(at..end)?;
        let text: &[u8] = raw.split(|byte: &u8| *byte == 0).next().unwrap_or(raw);
        if text.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(text).into_owned())
        }
    }
}

pub(super) fn word(bytes: &[u8], big_endian: bool) -> u64 {
    let mut value: u64 = 0;
    if big_endian {
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
    } else {
        for byte in bytes.iter().rev() {
            value = (value << 8) | u64::from(*byte);
        }
    }
    value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Segment {
    pub start: u64,
    pub size: u64,
    pub file_offset: u64,
    pub captured: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Protection {
    pub start: u64,
    pub end: u64,
    pub executable: bool,
}

pub(super) struct Memory<'a> {
    bytes: &'a [u8],
    segments: Vec<Segment>,
    protections: Vec<Protection>,
}

impl<'a> Memory<'a> {
    pub(super) fn new(
        bytes: &'a [u8],
        mut segments: Vec<Segment>,
        mut protections: Vec<Protection>,
    ) -> Self {
        let file_len: u64 = bytes.len() as u64;
        for segment in &mut segments {
            let available: u64 = file_len.saturating_sub(segment.file_offset);
            segment.captured = segment.captured.min(available).min(segment.size);
        }
        segments.sort_by_key(|segment: &Segment| (segment.start, segment.size));
        protections.sort_by_key(|range: &Protection| range.start);
        Self {
            bytes,
            segments,
            protections,
        }
    }

    fn segment(&self, address: u64) -> Option<&Segment> {
        let after: usize = self
            .segments
            .partition_point(|segment: &Segment| segment.start <= address);
        let segment: &Segment = self.segments.get(after.checked_sub(1)?)?;
        (address - segment.start < segment.size).then_some(segment)
    }

    pub(super) fn read_up_to(&self, address: u64, max: usize) -> Option<&'a [u8]> {
        let segment: &Segment = self.segment(address)?;
        let inside: u64 = address - segment.start;
        if inside >= segment.captured {
            return None;
        }
        let available: u64 = (segment.captured - inside).min(max as u64);
        let start: usize = usize::try_from(segment.file_offset.checked_add(inside)?).ok()?;
        let end: usize = start.checked_add(usize::try_from(available).ok()?)?;
        self.bytes.get(start..end)
    }

    pub(super) fn c_string(&self, address: u64, max: usize) -> Option<String> {
        let window: &[u8] = self.read_up_to(address, max)?;
        let end: usize = window.iter().position(|byte: &u8| *byte == 0)?;
        Some(String::from_utf8_lossy(&window[..end]).into_owned())
    }

    pub(super) fn is_executable(&self, address: u64) -> bool {
        if self.protections.is_empty() {
            return true;
        }
        let after: usize = self
            .protections
            .partition_point(|range: &Protection| range.start <= address);
        after
            .checked_sub(1)
            .and_then(|index: usize| self.protections.get(index))
            .is_some_and(|range: &Protection| address < range.end && range.executable)
    }

    pub(super) fn summary(&self) -> MemorySummary {
        let mut summary: MemorySummary = MemorySummary::default();
        for segment in &self.segments {
            summary.segments += 1;
            summary.described_bytes = summary.described_bytes.saturating_add(segment.size);
            summary.captured_bytes = summary.captured_bytes.saturating_add(segment.captured);
        }
        summary.executable_segments = self
            .protections
            .iter()
            .filter(|range: &&Protection| range.executable)
            .count() as u64;
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Range {
    start: u64,
    end: u64,
    module: usize,
}

#[derive(Debug, Default)]
pub(super) struct ModuleMap {
    ranges: Vec<Range>,
    modules: Vec<(String, u64)>,
}

impl ModuleMap {
    pub(super) fn add_module(&mut self, path: String, base: u64) -> usize {
        self.modules.push((path, base));
        self.modules.len() - 1
    }

    pub(super) fn add_range(&mut self, module: usize, start: u64, end: u64) {
        if start < end {
            self.ranges.push(Range { start, end, module });
        }
    }

    pub(super) fn finish(&mut self) {
        self.ranges
            .sort_by_key(|range: &Range| (range.start, range.end));
    }

    pub(super) fn locate(&self, address: u64) -> Option<Location> {
        let after: usize = self
            .ranges
            .partition_point(|range: &Range| range.start <= address);
        let range: &Range = self.ranges.get(after.checked_sub(1)?)?;
        if address >= range.end {
            return None;
        }
        let (path, base): &(String, u64) = self.modules.get(range.module)?;
        Some(Location {
            module: path.clone(),
            offset: address.wrapping_sub(*base),
        })
    }
}
