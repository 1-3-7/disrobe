use crate::error::{Error, Result};

pub(crate) const VM_MEMORY_SIZE: usize = 0x0004_0000;
const PROGRAM_WORK_SIZE: usize = 0x0003_C000;
const PROGRAM_SYSTEM_GLOBAL_ADDRESS: u32 = 0x0003_C000;
const PROGRAM_GLOBAL_SIZE: usize = 0x2000;
const PROGRAM_SYSTEM_GLOBAL_SIZE: usize = 0x40;
const PROGRAM_USER_GLOBAL_SIZE: u32 = (PROGRAM_GLOBAL_SIZE - PROGRAM_SYSTEM_GLOBAL_SIZE) as u32;
const MAX_PROGRAM_LENGTH: u32 = 0x0001_0000;
const MAX_FILTER_PROGRAMS: usize = 8_192;
const MAX_FILTER_INVOCATIONS: usize = 8_192;
const MAX_RECORD_LENGTH: usize = 0xffff;
const E8_ADDRESS_SPACE: u32 = 0x0100_0000;
const FILTER_WORK_PER_BYTE: u64 = 8;
const FILTER_WORK_BASE: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StandardFilter {
    Delta,
    E8,
    E8E9,
    Rgb,
    Audio,
}

impl StandardFilter {
    pub(crate) const fn slot(self) -> usize {
        match self {
            Self::Delta => 0,
            Self::E8 => 1,
            Self::E8E9 => 2,
            Self::Rgb => 3,
            Self::Audio => 4,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Delta => "delta",
            Self::E8 => "x86 e8",
            Self::E8E9 => "x86 e8/e9",
            Self::Rgb => "rgb",
            Self::Audio => "audio",
        }
    }
}

const FINGERPRINTS: [(u64, StandardFilter); 5] = [
    (0x0000_001d_0e06_077d, StandardFilter::Delta),
    (0x0000_0035_ad57_6887, StandardFilter::E8),
    (0x0000_0039_3cd7_e57e, StandardFilter::E8E9),
    (0x0000_0095_1c2c_5dc8, StandardFilter::Rgb),
    (0x0000_00d8_bc85_e701, StandardFilter::Audio),
];

struct RecordReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    window: u64,
    available: u32,
    exhausted: bool,
}

impl<'a> RecordReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            window: 0,
            available: 0,
            exhausted: false,
        }
    }

    fn fill(&mut self, want: u32) -> bool {
        while self.available < want {
            let Some(&byte) = self.bytes.get(self.offset) else {
                break;
            };
            self.window = (self.window << 8) | u64::from(byte);
            self.offset += 1;
            self.available += 8;
        }
        if self.available < want {
            self.exhausted = true;
            return false;
        }
        true
    }

    fn bits(&mut self, want: u32) -> u32 {
        if want > self.available && (self.exhausted || !self.fill(want)) {
            return 0;
        }
        self.available -= want;
        ((self.window >> self.available) & ((1u64 << want) - 1)) as u32
    }

    fn number(&mut self) -> u32 {
        match self.bits(2) {
            0 => self.bits(4),
            1 => {
                let low: u32 = self.bits(8);
                if low >= 16 {
                    low
                } else {
                    0xffff_ff00 | (low << 4) | self.bits(4)
                }
            }
            2 => self.bits(16),
            _ => self.bits(32),
        }
    }
}

#[derive(Debug)]
struct FilterProgram {
    filter: StandardFilter,
    usage_count: u32,
    old_filter_length: u32,
}

#[derive(Debug)]
struct FilterInvocation {
    block_start: u64,
    block_end: u64,
    block_length: u32,
    filter: StandardFilter,
    registers: [u32; 8],
}

#[derive(Debug, Default)]
pub(crate) struct FilterSet {
    programs: Vec<FilterProgram>,
    pending: Vec<FilterInvocation>,
    last_filter_num: u32,
}

impl FilterSet {
    pub(crate) const fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(crate) const fn len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn invocation_counts(&self) -> [usize; 5] {
        let mut counts: [usize; 5] = [0usize; 5];
        for invocation in &self.pending {
            counts[invocation.filter.slot()] += 1;
        }
        counts
    }

    pub(crate) fn record(&mut self, flags: u8, code: &[u8], position: u64) -> Result<()> {
        if code.len() > MAX_RECORD_LENGTH {
            return Err(Error::Decompression(format!(
                "rar 2.9/3.x filter record of {} bytes exceeds the {MAX_RECORD_LENGTH} byte limit",
                code.len()
            )));
        }
        let mut reader: RecordReader<'_> = RecordReader::new(code);

        let index: usize = if flags & 0x80 == 0 {
            self.last_filter_num as usize
        } else {
            let raw: u32 = reader.number();
            let selected: u32 = if raw == 0 {
                self.reset(position);
                0
            } else {
                raw - 1
            };
            if selected as usize > self.programs.len() {
                return Err(Error::Decompression(format!(
                    "rar 2.9/3.x filter record selects program {selected} beyond the {} defined",
                    self.programs.len()
                )));
            }
            self.last_filter_num = selected;
            selected as usize
        };
        let known: bool = index < self.programs.len();
        if known {
            let program: &mut FilterProgram = &mut self.programs[index];
            program.usage_count = program.usage_count.saturating_add(1);
        } else if index != self.programs.len() {
            return Err(Error::Decompression(format!(
                "rar 2.9/3.x filter record reuses undefined program index {index}"
            )));
        }

        let block_start: u64 = u64::from(reader.number())
            .checked_add(position)
            .and_then(|start: u64| {
                if flags & 0x40 == 0 {
                    Some(start)
                } else {
                    start.checked_add(258)
                }
            })
            .ok_or_else(|| {
                Error::Decompression("rar 2.9/3.x filter block start overflows".to_owned())
            })?;
        let block_length: u32 = if flags & 0x20 != 0 {
            reader.number()
        } else if known {
            self.programs[index].old_filter_length
        } else {
            0
        };
        if block_length as usize > VM_MEMORY_SIZE {
            return Err(Error::Decompression(format!(
                "rar 2.9/3.x filter block length {block_length} exceeds the {VM_MEMORY_SIZE} byte filter memory"
            )));
        }
        let block_end: u64 = block_start
            .checked_add(u64::from(block_length))
            .ok_or_else(|| {
                Error::Decompression("rar 2.9/3.x filter block end overflows".to_owned())
            })?;

        let mut registers: [u32; 8] = [0u32; 8];
        registers[3] = PROGRAM_SYSTEM_GLOBAL_ADDRESS;
        registers[4] = block_length;
        registers[5] = if known {
            self.programs[index].usage_count
        } else {
            0
        };
        registers[7] = VM_MEMORY_SIZE as u32;
        if flags & 0x10 != 0 {
            let mask: u32 = reader.bits(7);
            for (slot, register) in registers.iter_mut().enumerate().take(7) {
                if mask & (1 << slot) != 0 {
                    *register = reader.number();
                }
            }
        }

        if !known {
            let length: u32 = reader.number();
            if length == 0 || length > MAX_PROGRAM_LENGTH {
                return Err(Error::Decompression(format!(
                    "rar 2.9/3.x filter program length {length} is outside 1..={MAX_PROGRAM_LENGTH}"
                )));
            }
            let mut program_bytes: Vec<u8> = Vec::with_capacity(length as usize);
            for _ in 0..length {
                program_bytes.push(reader.bits(8) as u8);
            }
            if reader.exhausted {
                return Err(Error::Decompression(
                    "rar 2.9/3.x filter record ended inside its program body".to_owned(),
                ));
            }
            if self.programs.len() >= MAX_FILTER_PROGRAMS {
                return Err(Error::Decompression(format!(
                    "rar 2.9/3.x member defines more than {MAX_FILTER_PROGRAMS} filter programs"
                )));
            }
            self.programs.push(compile(&program_bytes)?);
        }
        self.programs[index].old_filter_length = block_length;

        if flags & 0x08 != 0 {
            let global_length: u32 = reader.number();
            if global_length > PROGRAM_USER_GLOBAL_SIZE {
                return Err(Error::Decompression(format!(
                    "rar 2.9/3.x filter global data of {global_length} bytes exceeds {PROGRAM_USER_GLOBAL_SIZE}"
                )));
            }
            for _ in 0..global_length {
                let _discarded: u32 = reader.bits(8);
            }
        }

        if reader.exhausted {
            return Err(Error::Decompression(
                "rar 2.9/3.x filter record ended before its fields were read".to_owned(),
            ));
        }
        if self.pending.len() >= MAX_FILTER_INVOCATIONS {
            return Err(Error::Decompression(format!(
                "rar 2.9/3.x member queues more than {MAX_FILTER_INVOCATIONS} filter invocations"
            )));
        }
        self.pending.push(FilterInvocation {
            block_start,
            block_end,
            block_length,
            filter: self.programs[index].filter,
            registers,
        });
        Ok(())
    }

    fn reset(&mut self, position: u64) {
        self.programs.clear();
        self.pending
            .retain(|invocation: &FilterInvocation| invocation.block_end <= position);
        self.last_filter_num = 0;
    }

    pub(crate) fn emit(&self, window: &[u8], want: usize) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(want as u64));
        let mut memory: Vec<u8> = vec![0u8; VM_MEMORY_SIZE];
        let mut budget: u64 = (want as u64)
            .saturating_mul(FILTER_WORK_PER_BYTE)
            .saturating_add(FILTER_WORK_BASE);
        let mut cursor: usize = 0;
        let mut index: usize = 0;

        while index < self.pending.len() {
            let invocation: &FilterInvocation = &self.pending[index];
            let start: usize = usize::try_from(invocation.block_start).map_err(
                |_e: std::num::TryFromIntError| {
                    Error::Decompression(
                        "rar 2.9/3.x filter block start exceeds the address space".to_owned(),
                    )
                },
            )?;
            if start < cursor {
                return Err(Error::Decompression(format!(
                    "rar 2.9/3.x filter block at {start} overlaps the previous filtered block ending at {cursor}"
                )));
            }
            let end: usize = start
                .checked_add(invocation.block_length as usize)
                .ok_or_else(|| {
                    Error::Decompression("rar 2.9/3.x filter block end overflows".to_owned())
                })?;
            if end > window.len() {
                return Err(Error::Decompression(format!(
                    "rar 2.9/3.x filter block {start}..{end} runs past the {} decoded bytes",
                    window.len()
                )));
            }
            out.extend_from_slice(&window[cursor..start]);

            let file_offset: u32 = out.len() as u32;
            memory[..invocation.block_length as usize].copy_from_slice(&window[start..end]);
            let (mut address, mut length): (usize, usize) =
                execute(invocation, &mut memory, file_offset, &mut budget)?;
            index += 1;

            while let Some(next) = self.pending.get(index) {
                if next.block_start != invocation.block_start
                    || next.block_length as usize != length
                {
                    break;
                }
                memory.copy_within(address..address + length, 0);
                let chained: (usize, usize) = execute(next, &mut memory, file_offset, &mut budget)?;
                address = chained.0;
                length = chained.1;
                index += 1;
            }

            let filtered: &[u8] = memory.get(address..address + length).ok_or_else(|| {
                Error::Decompression(
                    "rar 2.9/3.x filter reported output outside its memory window".to_owned(),
                )
            })?;
            out.extend_from_slice(filtered);
            cursor = end;
        }
        out.extend_from_slice(&window[cursor..]);
        Ok(out)
    }
}

fn compile(code: &[u8]) -> Result<FilterProgram> {
    let Some(&checksum) = code.first() else {
        return Err(Error::Decompression(
            "rar 2.9/3.x filter program is empty".to_owned(),
        ));
    };
    let computed: u8 = code[1..].iter().fold(0u8, |acc: u8, &byte: &u8| acc ^ byte);
    if computed != checksum {
        return Err(Error::Decompression(
            "rar 2.9/3.x filter program checksum does not match its body".to_owned(),
        ));
    }
    let fingerprint: u64 = u64::from(crc32fast::hash(code)) | ((code.len() as u64) << 32);
    let Some(&(_, filter)) = FINGERPRINTS
        .iter()
        .find(|&&(candidate, _): &&(u64, StandardFilter)| candidate == fingerprint)
    else {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x member carries filter program {fingerprint:#014x} ({} bytes), which is not one of the canonical delta, x86 e8, x86 e8/e9, rgb and audio transforms; disrobe identifies filter programs by exact length and crc32 and does not execute rarvm bytecode",
            code.len()
        )));
    };
    Ok(FilterProgram {
        filter,
        usage_count: 0,
        old_filter_length: 0,
    })
}

fn execute(
    invocation: &FilterInvocation,
    memory: &mut [u8],
    file_offset: u32,
    budget: &mut u64,
) -> Result<(usize, usize)> {
    let length: u32 = invocation.registers[4];
    let cost: u64 = u64::from(length).saturating_mul(4).saturating_add(64);
    *budget = budget.checked_sub(cost).ok_or_else(|| {
        Error::Decompression(
            "rar 2.9/3.x filter work exceeded the budget derived from the declared output size"
                .to_owned(),
        )
    })?;
    let address: usize = match invocation.filter {
        StandardFilter::E8 => filter_e8(memory, length, file_offset, false),
        StandardFilter::E8E9 => filter_e8(memory, length, file_offset, true),
        StandardFilter::Delta => filter_delta(memory, length, invocation.registers[0]),
        StandardFilter::Rgb => filter_rgb(
            memory,
            length,
            invocation.registers[0],
            invocation.registers[1],
        ),
        StandardFilter::Audio => filter_audio(memory, length, invocation.registers[0]),
    }?;
    Ok((address, length as usize))
}

fn refuse(filter: StandardFilter, detail: &str) -> Error {
    Error::Decompression(format!(
        "rar 2.9/3.x {} filter refused: {detail}",
        filter.label()
    ))
}

fn filter_e8(memory: &mut [u8], length: u32, file_offset: u32, e9_also: bool) -> Result<usize> {
    let len: usize = length as usize;
    if len > PROGRAM_WORK_SIZE || len <= 4 {
        return Err(refuse(
            if e9_also {
                StandardFilter::E8E9
            } else {
                StandardFilter::E8
            },
            &format!("block length {len} is outside 5..={PROGRAM_WORK_SIZE}"),
        ));
    }
    let mut index: usize = 0;
    while index <= len - 5 {
        let current: u8 = memory[index];
        if current == 0xe8 || (e9_also && current == 0xe9) {
            let position: u32 = file_offset.wrapping_add(index as u32).wrapping_add(1);
            let raw: [u8; 4] = [
                memory[index + 1],
                memory[index + 2],
                memory[index + 3],
                memory[index + 4],
            ];
            let address: i32 = i32::from_le_bytes(raw);
            if address < 0 {
                if position >= (address as u32).wrapping_neg() {
                    let restored: u32 = (address as u32).wrapping_add(E8_ADDRESS_SPACE);
                    memory[index + 1..index + 5].copy_from_slice(&restored.to_le_bytes());
                }
            } else if (address as u32) < E8_ADDRESS_SPACE {
                let restored: u32 = (address as u32).wrapping_sub(position);
                memory[index + 1..index + 5].copy_from_slice(&restored.to_le_bytes());
            }
            index += 4;
        }
        index += 1;
    }
    Ok(0)
}

fn filter_delta(memory: &mut [u8], length: u32, channels: u32) -> Result<usize> {
    let len: usize = length as usize;
    if len > PROGRAM_WORK_SIZE / 2 {
        return Err(refuse(
            StandardFilter::Delta,
            &format!("block length {len} exceeds {}", PROGRAM_WORK_SIZE / 2),
        ));
    }
    if channels == 0 || channels > length {
        return Err(refuse(
            StandardFilter::Delta,
            &format!("channel count {channels} is outside 1..={length}"),
        ));
    }
    let step: usize = channels as usize;
    let mut source: usize = 0;
    for channel in 0..step {
        let mut previous: u8 = 0;
        let mut target: usize = channel;
        while target < len {
            if source >= len {
                return Err(refuse(
                    StandardFilter::Delta,
                    "source and destination blocks overlap",
                ));
            }
            previous = previous.wrapping_sub(memory[source]);
            memory[len + target] = previous;
            source += 1;
            target += step;
        }
    }
    Ok(len)
}

fn filter_rgb(
    memory: &mut [u8],
    block_length: u32,
    stride: u32,
    byte_offset: u32,
) -> Result<usize> {
    let len: usize = block_length as usize;
    if len > PROGRAM_WORK_SIZE / 2 || stride > block_length || len < 3 || byte_offset > 2 {
        return Err(refuse(
            StandardFilter::Rgb,
            &format!(
                "block length {len}, stride {stride} and byte offset {byte_offset} are outside the supported ranges"
            ),
        ));
    }
    let span: usize = stride as usize;
    let mut source: usize = 0;
    for plane in 0..3usize {
        let mut value: u8 = 0;
        let mut target: usize = plane;
        while target < len {
            if source >= len {
                return Err(refuse(
                    StandardFilter::Rgb,
                    "source and destination blocks overlap",
                ));
            }
            if target >= span {
                let base: usize = len + target - span;
                let previous: i32 = i32::from(memory[base]);
                let ahead: i32 = i32::from(memory[base + 3]);
                let delta1: i32 = (ahead - previous).abs();
                let delta2: i32 = (i32::from(value) - previous).abs();
                let delta3: i32 = (ahead - previous + i32::from(value) - previous).abs();
                if delta1 > delta2 || delta1 > delta3 {
                    value = if delta2 <= delta3 {
                        memory[base + 3]
                    } else {
                        memory[base]
                    };
                }
            }
            value = value.wrapping_sub(memory[source]);
            memory[len + target] = value;
            source += 1;
            target += 3;
        }
    }
    let mut index: usize = byte_offset as usize;
    while index + 2 < len {
        let middle: u8 = memory[len + index + 1];
        memory[len + index] = memory[len + index].wrapping_add(middle);
        memory[len + index + 2] = memory[len + index + 2].wrapping_add(middle);
        index += 3;
    }
    Ok(len)
}

#[derive(Default)]
struct AudioState {
    weight: [i32; 3],
    delta: [i16; 3],
    error: [i32; 7],
    last_delta: i8,
    last_byte: u8,
    count: u32,
}

fn filter_audio(memory: &mut [u8], length: u32, channels: u32) -> Result<usize> {
    let len: usize = length as usize;
    if len > PROGRAM_WORK_SIZE / 2 {
        return Err(refuse(
            StandardFilter::Audio,
            &format!("block length {len} exceeds {}", PROGRAM_WORK_SIZE / 2),
        ));
    }
    if channels == 0 || channels > length {
        return Err(refuse(
            StandardFilter::Audio,
            &format!("channel count {channels} is outside 1..={length}"),
        ));
    }
    let step: usize = channels as usize;
    let mut source: usize = 0;
    for channel in 0..step {
        let mut state: AudioState = AudioState::default();
        let mut target: usize = channel;
        while target < len {
            if source >= len {
                return Err(refuse(
                    StandardFilter::Audio,
                    "source and destination blocks overlap",
                ));
            }
            let delta: i8 = memory[source] as i8;
            source += 1;
            state.delta[2] = state.delta[1];
            state.delta[1] = i16::from(state.last_delta).wrapping_sub(state.delta[0]);
            state.delta[0] = i16::from(state.last_delta);
            let predicted: i32 = ((8 * i32::from(state.last_byte)
                + state.weight[0] * i32::from(state.delta[0])
                + state.weight[1] * i32::from(state.delta[1])
                + state.weight[2] * i32::from(state.delta[2]))
                >> 3)
                & 0xff;
            let value: u8 = (predicted - i32::from(delta)) as u8;
            let error: i32 = i32::from(delta) * 8;
            state.error[0] += error.abs();
            state.error[1] += (error - i32::from(state.delta[0])).abs();
            state.error[2] += (error + i32::from(state.delta[0])).abs();
            state.error[3] += (error - i32::from(state.delta[1])).abs();
            state.error[4] += (error + i32::from(state.delta[1])).abs();
            state.error[5] += (error - i32::from(state.delta[2])).abs();
            state.error[6] += (error + i32::from(state.delta[2])).abs();
            state.last_delta = value.wrapping_sub(state.last_byte) as i8;
            state.last_byte = value;
            memory[len + target] = value;
            if state.count.trailing_zeros() >= 5 {
                let mut best: usize = 0;
                for candidate in 1..7usize {
                    if state.error[candidate] < state.error[best] {
                        best = candidate;
                    }
                }
                state.error = [0i32; 7];
                match best {
                    1 if state.weight[0] >= -16 => state.weight[0] -= 1,
                    2 if state.weight[0] < 16 => state.weight[0] += 1,
                    3 if state.weight[1] >= -16 => state.weight[1] -= 1,
                    4 if state.weight[1] < 16 => state.weight[1] += 1,
                    5 if state.weight[2] >= -16 => state.weight[2] -= 1,
                    6 if state.weight[2] < 16 => state.weight[2] += 1,
                    _ => {}
                }
            }
            state.count = state.count.wrapping_add(1);
            target += step;
        }
    }
    Ok(len)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn program(filter: StandardFilter) -> (usize, u32) {
        let entry: (u64, StandardFilter) = *FINGERPRINTS
            .iter()
            .find(|&&(_, kind): &&(u64, StandardFilter)| kind == filter)
            .unwrap();
        ((entry.0 >> 32) as usize, entry.0 as u32)
    }

    #[test]
    fn canonical_fingerprints_pair_length_with_crc32() {
        assert_eq!(program(StandardFilter::Delta), (29, 0x0e06_077d));
        assert_eq!(program(StandardFilter::E8), (53, 0xad57_6887));
        assert_eq!(program(StandardFilter::E8E9), (57, 0x3cd7_e57e));
        assert_eq!(program(StandardFilter::Rgb), (149, 0x1c2c_5dc8));
        assert_eq!(program(StandardFilter::Audio), (216, 0xbc85_e701));
    }

    #[test]
    fn record_reader_decodes_every_rarvm_number_width() {
        let mut reader: RecordReader<'_> = RecordReader::new(&[0b0010_1000]);
        assert_eq!(reader.number(), 0b1010);

        let mut reader: RecordReader<'_> = RecordReader::new(&[0b0100_1000, 0b0000_0000]);
        assert_eq!(reader.number(), 0x20);

        let mut reader: RecordReader<'_> = RecordReader::new(&[0b0100_0000, 0b1000_0000]);
        assert_eq!(reader.number(), 0xffff_ff20);

        let mut reader: RecordReader<'_> = RecordReader::new(&[0b1011_1111, 0xff, 0xc0]);
        assert_eq!(reader.number(), 0xffff);

        let mut reader: RecordReader<'_> = RecordReader::new(&[0xff, 0xff, 0xff, 0xff, 0xc0]);
        assert_eq!(reader.number(), 0xffff_ffff);
    }

    #[test]
    fn record_reader_reports_exhaustion_rather_than_padding_silently() {
        let mut reader: RecordReader<'_> = RecordReader::new(&[0xc0]);
        assert_eq!(reader.number(), 0);
        assert!(reader.exhausted);
    }

    #[test]
    fn an_unknown_program_names_the_fingerprint_instead_of_executing_it() {
        let body: [u8; 4] = [0x01, 0x02, 0x03, 0x00];
        let checksum: u8 = body.iter().fold(0u8, |acc: u8, &b: &u8| acc ^ b);
        let mut code: Vec<u8> = vec![checksum];
        code.extend_from_slice(&body);
        let error: Error = compile(&code).unwrap_err();
        let text: String = error.to_string();
        assert!(text.contains("not one of the canonical"), "{text}");
        assert!(text.contains("does not execute rarvm bytecode"), "{text}");
    }

    #[test]
    fn a_program_whose_checksum_disagrees_with_its_body_is_refused() {
        let error: Error = compile(&[0x00, 0x11, 0x22]).unwrap_err();
        assert!(
            error.to_string().contains("checksum does not match"),
            "{error}"
        );
    }

    #[test]
    fn delta_reverses_channel_interleaving() {
        let mut memory: Vec<u8> = vec![0u8; VM_MEMORY_SIZE];
        memory[0] = 0xff;
        memory[1] = 0xff;
        memory[2] = 0xfe;
        memory[3] = 0xff;
        let address: usize = filter_delta(&mut memory, 4, 2).unwrap();
        assert_eq!(address, 4);
        assert_eq!(&memory[4..8], &[0x01, 0x02, 0x02, 0x03]);
    }

    #[test]
    fn delta_refuses_a_channel_count_that_would_spin_the_outer_loop() {
        let mut memory: Vec<u8> = vec![0u8; VM_MEMORY_SIZE];
        let error: Error = filter_delta(&mut memory, 16, 0xffff_ffff).unwrap_err();
        assert!(error.to_string().contains("channel count"), "{error}");
    }

    #[test]
    fn audio_refuses_a_channel_count_that_would_spin_the_outer_loop() {
        let mut memory: Vec<u8> = vec![0u8; VM_MEMORY_SIZE];
        let error: Error = filter_audio(&mut memory, 16, 0xffff_ffff).unwrap_err();
        assert!(error.to_string().contains("channel count"), "{error}");
    }

    #[test]
    fn e8_refuses_a_block_larger_than_the_filter_work_area() {
        let mut memory: Vec<u8> = vec![0u8; VM_MEMORY_SIZE];
        let error: Error = filter_e8(&mut memory, 0x0003_ffff, 0, false).unwrap_err();
        assert!(error.to_string().contains("block length"), "{error}");
    }

    #[test]
    fn e8_rewrites_only_absolute_targets_inside_the_address_space() {
        let mut memory: Vec<u8> = vec![0u8; VM_MEMORY_SIZE];
        memory[0] = 0xe8;
        memory[1..5].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        memory[5] = 0xe9;
        memory[6..10].copy_from_slice(&0x0000_3000u32.to_le_bytes());
        filter_e8(&mut memory, 16, 0x100, false).unwrap();
        assert_eq!(
            u32::from_le_bytes([memory[1], memory[2], memory[3], memory[4]]),
            0x0000_2000u32.wrapping_sub(0x101)
        );
        assert_eq!(
            u32::from_le_bytes([memory[6], memory[7], memory[8], memory[9]]),
            0x0000_3000
        );
    }

    #[test]
    fn random_filter_records_are_refused_without_panicking() {
        let mut state: u64 = 0x5241_5256_4d5f_4655;
        let mut next = move || -> u64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted: usize = 0;
        for _ in 0..40_000 {
            let length: usize = (next() % 96) as usize;
            let code: Vec<u8> = (0..length).map(|_| (next() >> 24) as u8).collect();
            let flags: u8 = (next() >> 32) as u8;
            let position: u64 = next() % 0x0002_0000;
            let mut set: FilterSet = FilterSet::default();
            if set.record(flags, &code, position).is_ok() {
                accepted += 1;
                let window: Vec<u8> = vec![0u8; 4_096];
                let _ = set.emit(&window, 4_096);
            }
        }
        assert!(
            accepted < 40_000,
            "random bytes must not all parse as canonical filter records"
        );
    }

    fn delta_invocation(start: u64, length: u32) -> FilterInvocation {
        FilterInvocation {
            block_start: start,
            block_end: start + u64::from(length),
            block_length: length,
            filter: StandardFilter::Delta,
            registers: [1, 0, 0, 0, length, 0, 0, 0],
        }
    }

    #[test]
    fn filters_sharing_a_start_and_length_run_over_the_previous_filtered_bytes() {
        let window: Vec<u8> = vec![1u8, 1, 1, 1];

        let mut single: FilterSet = FilterSet::default();
        single.programs.push(FilterProgram {
            filter: StandardFilter::Delta,
            usage_count: 0,
            old_filter_length: 4,
        });
        single.pending.push(delta_invocation(0, 4));
        assert_eq!(single.emit(&window, 4).unwrap(), vec![255u8, 254, 253, 252]);

        let mut chained: FilterSet = FilterSet::default();
        chained.programs.push(FilterProgram {
            filter: StandardFilter::Delta,
            usage_count: 0,
            old_filter_length: 4,
        });
        chained.pending.push(delta_invocation(0, 4));
        chained.pending.push(delta_invocation(0, 4));
        assert_eq!(
            chained.emit(&window, 4).unwrap(),
            vec![1u8, 3, 6, 10],
            "the second invocation must transform the first invocation's output, not the raw window"
        );
    }

    #[test]
    fn a_following_filter_at_a_different_start_is_not_chained() {
        let window: Vec<u8> = vec![1u8, 1, 1, 1, 1, 1, 1, 1];
        let mut set: FilterSet = FilterSet::default();
        set.programs.push(FilterProgram {
            filter: StandardFilter::Delta,
            usage_count: 0,
            old_filter_length: 4,
        });
        set.pending.push(delta_invocation(0, 4));
        set.pending.push(delta_invocation(4, 4));
        assert_eq!(
            set.emit(&window, 8).unwrap(),
            vec![255u8, 254, 253, 252, 255, 254, 253, 252]
        );
    }

    #[test]
    fn a_filter_block_past_the_decoded_output_is_refused() {
        let mut set: FilterSet = FilterSet::default();
        set.programs.push(FilterProgram {
            filter: StandardFilter::E8,
            usage_count: 0,
            old_filter_length: 0,
        });
        set.pending.push(FilterInvocation {
            block_start: 8,
            block_end: 4_104,
            block_length: 4_096,
            filter: StandardFilter::E8,
            registers: [0, 0, 0, 0, 4_096, 0, 0, 0],
        });
        let window: Vec<u8> = vec![0u8; 64];
        let error: Error = set.emit(&window, 64).unwrap_err();
        assert!(
            error.to_string().contains("runs past the 64 decoded bytes"),
            "{error}"
        );
    }

    #[test]
    fn the_filter_work_budget_refuses_a_flood_of_invocations() {
        let mut set: FilterSet = FilterSet::default();
        set.programs.push(FilterProgram {
            filter: StandardFilter::E8,
            usage_count: 0,
            old_filter_length: 0,
        });
        for slot in 0..64u64 {
            set.pending.push(FilterInvocation {
                block_start: slot,
                block_end: slot,
                block_length: 0,
                filter: StandardFilter::E8,
                registers: [0, 0, 0, 0, 0x0002_0000, 0, 0, 0],
            });
        }
        let window: Vec<u8> = vec![0u8; 128];
        let error: Error = set.emit(&window, 128).unwrap_err();
        assert!(error.to_string().contains("work exceeded"), "{error}");
    }
}
