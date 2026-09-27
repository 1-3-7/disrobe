use disrobe_bytes::ByteReader;
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
            let scalar: Option<char> = read_wide_unit(&mut reader, encoding);
            if reader.position() == position {
                break;
            }
            let accepted: Option<char> = scalar
                .filter(|&candidate: &char| is_printable_ascii_scalar(candidate))
                .filter(|_| chars.len() * unit < limits.max_run_bytes);
            let Some(candidate): Option<char> = accepted else {
                push_wide_run(base, encoding, run_start, &chars, limits, out.as_mut());
                run_start = None;
                chars.clear();
                continue;
            };
            if run_start.is_none() {
                run_start = Some(position);
            }
            chars.push(candidate);
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

#[inline]
const fn is_printable_ascii_scalar(scalar: char) -> bool {
    matches!(scalar, ' '..='~')
}

#[inline]
const fn is_text_scalar(scalar: char) -> bool {
    matches!(scalar, ' '..='~' | '\u{a0}'..='\u{d7ff}' | '\u{e000}'..='\u{fffc}')
}
