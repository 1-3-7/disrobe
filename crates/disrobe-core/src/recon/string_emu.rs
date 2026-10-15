use serde::{Deserialize, Serialize};

const MIN_RUN_CHARS: usize = 4;
const MAX_RUNS: usize = 4096;
const MAX_RUN_BYTES: usize = 64 << 10;

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
    let context: WideContext<'_> = WideContext {
        bytes,
        base,
        encoding,
        limits,
    };
    match encoding {
        StringEncoding::Utf16Le => {
            context.runs(|unit: [u8; 2]| u32::from(u16::from_le_bytes(unit)))
        }
        StringEncoding::Utf16Be => {
            context.runs(|unit: [u8; 2]| u32::from(u16::from_be_bytes(unit)))
        }
        StringEncoding::Utf32Le => context.runs(u32::from_le_bytes),
        StringEncoding::Utf32Be => context.runs(u32::from_be_bytes),
        StringEncoding::Ascii | StringEncoding::Utf8 | StringEncoding::Bytes => Vec::new(),
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct WideRun {
    start: Option<usize>,
    chars: usize,
}

#[derive(Debug, Clone, Copy)]
struct WideContext<'a> {
    bytes: &'a [u8],
    base: u64,
    encoding: StringEncoding,
    limits: &'a RunLimits,
}

impl WideContext<'_> {
    fn runs<const UNIT: usize>(self, decode: impl Fn([u8; UNIT]) -> u32) -> Vec<DecodedString> {
        let mut out: Vec<DecodedString> = Vec::new();
        for alignment in 0..UNIT {
            let Some(aligned): Option<&[u8]> = self
                .bytes
                .get(alignment..)
                .filter(|rest: &&[u8]| !rest.is_empty())
            else {
                break;
            };
            let mut run: WideRun = WideRun::default();
            for (index, &code_unit) in aligned.as_chunks::<UNIT>().0.iter().enumerate() {
                if out.len() >= self.limits.max_runs {
                    return out;
                }
                if (0x20..=0x7e).contains(&decode(code_unit))
                    && run.chars * UNIT < self.limits.max_run_bytes
                {
                    run.start.get_or_insert(alignment + index * UNIT);
                    run.chars += 1;
                    continue;
                }
                if run.start.is_some() {
                    self.push(run, &decode, &mut out);
                    run = WideRun::default();
                }
            }
            self.push(run, &decode, &mut out);
        }
        out
    }

    fn push<const UNIT: usize>(
        self,
        run: WideRun,
        decode: &impl Fn([u8; UNIT]) -> u32,
        out: &mut Vec<DecodedString>,
    ) {
        let Some(start): Option<usize> = run.start else {
            return;
        };
        if run.chars < self.limits.min_chars || out.len() >= self.limits.max_runs {
            return;
        }
        let Some(raw): Option<&[u8]> = self.bytes.get(start..start + run.chars * UNIT) else {
            return;
        };
        let text: String = raw
            .as_chunks::<UNIT>()
            .0
            .iter()
            .map(|&code_unit: &[u8; UNIT]| char::from(decode(code_unit) as u8))
            .collect();
        out.push(DecodedString {
            address: self.base.wrapping_add(start as u64),
            encoding: self.encoding,
            bytes: raw.to_vec(),
            text: Some(text),
        });
    }
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

#[inline]
const fn is_printable_ascii_scalar(scalar: char) -> bool {
    matches!(scalar, ' '..='~')
}

#[inline]
const fn is_text_scalar(scalar: char) -> bool {
    matches!(scalar, ' '..='~' | '\u{a0}'..='\u{d7ff}' | '\u{e000}'..='\u{fffc}')
}

#[cfg(test)]
mod tests {
    use disrobe_bytes::ByteReader;

    use super::{
        DecodedString, RunLimits, StringEncoding, is_printable_ascii_scalar, unit_runs_wide,
    };

    fn reference_unit_runs_wide(
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
                let raw: Option<u32> = match encoding {
                    StringEncoding::Utf16Le => reader.read_u16_le().ok().map(u32::from),
                    StringEncoding::Utf16Be => reader.read_u16_be().ok().map(u32::from),
                    StringEncoding::Utf32Le => reader.read_u32_le().ok(),
                    StringEncoding::Utf32Be => reader.read_u32_be().ok(),
                    StringEncoding::Ascii | StringEncoding::Utf8 | StringEncoding::Bytes => None,
                };
                if reader.position() == position {
                    break;
                }
                let accepted: Option<char> = raw
                    .and_then(char::from_u32)
                    .filter(|&candidate: &char| is_printable_ascii_scalar(candidate))
                    .filter(|_| chars.len() * unit < limits.max_run_bytes);
                let Some(candidate): Option<char> = accepted else {
                    reference_push(base, encoding, run_start, &chars, limits, &mut out);
                    run_start = None;
                    chars.clear();
                    continue;
                };
                if run_start.is_none() {
                    run_start = Some(position);
                }
                chars.push(candidate);
            }
            reference_push(base, encoding, run_start, &chars, limits, &mut out);
        }
        out
    }

    fn reference_push(
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
        let mut raw: Vec<u8> = Vec::new();
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

    fn wide_inputs() -> Vec<Vec<u8>> {
        let mut inputs: Vec<Vec<u8>> = vec![Vec::new(), vec![0x41], vec![0x41, 0x00]];
        let mut structured: Vec<u8> = Vec::new();
        for word in [
            "Hello",
            "wide world",
            "ab",
            "x",
            "Configuration\\Run",
            "~ !",
        ] {
            for &byte in word.as_bytes() {
                structured.extend_from_slice(&[byte, 0x00]);
            }
            structured.extend_from_slice(&[0x00, 0x00, 0xff]);
            for &byte in word.as_bytes() {
                structured.extend_from_slice(&[0x00, 0x00, 0x00, byte]);
            }
            structured.extend_from_slice(&[0x1f, 0x00, 0x7f, 0x00, 0x80, 0x00]);
        }
        inputs.push(structured);
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        for length in [7usize, 64, 333, 4096] {
            let random: Vec<u8> = (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let byte: u8 = state.to_le_bytes()[0];
                    if byte < 0x80 { byte & 0x7f } else { 0x00 }
                })
                .collect();
            inputs.push(random);
        }
        inputs
    }

    #[test]
    fn wide_runs_match_the_reader_based_reference() {
        let limit_sets: [RunLimits; 3] = [
            RunLimits::default(),
            RunLimits {
                min_chars: 2,
                max_runs: 3,
                max_run_bytes: 8,
            },
            RunLimits {
                min_chars: 1,
                max_runs: 1 << 16,
                max_run_bytes: 6,
            },
        ];
        let encodings: [StringEncoding; 4] = [
            StringEncoding::Utf16Le,
            StringEncoding::Utf16Be,
            StringEncoding::Utf32Le,
            StringEncoding::Utf32Be,
        ];
        let mut compared_runs: usize = 0;
        for input in wide_inputs() {
            for limits in &limit_sets {
                for encoding in encodings {
                    let expected: Vec<DecodedString> =
                        reference_unit_runs_wide(&input, 0x1000, encoding, limits);
                    compared_runs += expected.len();
                    assert_eq!(
                        unit_runs_wide(&input, 0x1000, encoding, limits),
                        expected,
                        "{encoding:?} {input:02x?}"
                    );
                }
            }
        }
        assert!(compared_runs > 100, "only {compared_runs} runs compared");
    }
}
