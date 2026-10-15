use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STANDARD, STANDARD_NO_PAD as B64_NO_PAD};
use serde::{Deserialize, Serialize};

pub const STRINGS_SCHEMA: &str = "disrobe.strings/v0";

pub const DEFAULT_MIN_LEN: usize = 4;
const XOR_MIN_PRINTABLE_RATIO: f64 = 0.95;
const XOR_MIN_DICT_HITS: usize = 2;
const XOR_MIN_RUN_LEN: usize = 6;
const MAX_DECODE_RECURSE_LEN: usize = 1 << 16;
const XOR_HISTOGRAM_MIN_RUN: usize = 1024;

#[must_use]
pub fn head(text: &str, max_bytes: usize) -> &str {
    let mut end: usize = text.len().min(max_bytes);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tag", rename_all = "snake_case")]
pub enum Tagging {
    Plain { wide: bool },
    Xor { key: u8 },
    Base64,
    Rot { n: u8 },
    StackString,
    Codec { scheme: String },
}

impl Tagging {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Plain { wide: false } => "plain".to_owned(),
            Self::Plain { wide: true } => "plain:wide".to_owned(),
            Self::Xor { key } => format!("xor:{key:#04x}"),
            Self::Base64 => "base64".to_owned(),
            Self::Rot { n } => format!("rot:{n}"),
            Self::StackString => "stack-string".to_owned(),
            Self::Codec { scheme } => format!("codec:{scheme}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    #[serde(flatten)]
    pub tagging: Tagging,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringsReport {
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub byte_len: usize,
    pub min_len: usize,
    pub total: usize,
    pub strings: Vec<ExtractedString>,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub min_len: usize,
    pub decode: bool,
}

impl Default for Options {
    #[inline]
    fn default() -> Self {
        Self {
            min_len: DEFAULT_MIN_LEN,
            decode: true,
        }
    }
}

#[inline]
const fn is_printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7e) || matches!(b, b'\t' | b'\n' | b'\r')
}

#[inline]
const fn is_strong_printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7e)
}

fn extract_ascii(bytes: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if is_printable(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            push_run(bytes, s, i, min_len, false, out);
        }
    }
    if let Some(s) = start.take() {
        push_run(bytes, s, bytes.len(), min_len, false, out);
    }
}

fn push_run(
    bytes: &[u8],
    start: usize,
    end: usize,
    min_len: usize,
    wide: bool,
    out: &mut Vec<ExtractedString>,
) {
    let run: &[u8] = &bytes[start..end];
    if run.len() < min_len {
        return;
    }
    let value: String = String::from_utf8_lossy(run).into_owned();
    let unpadded: &str = value.trim_start_matches(['\t', '\n', '\r']);
    let leading: usize = value.len() - unpadded.len();
    let trimmed: &str = unpadded.trim_end_matches(['\t', '\n', '\r']);
    if trimmed.chars().count() < min_len {
        return;
    }
    out.push(ExtractedString {
        value: trimmed.to_owned(),
        offset: start + leading,
        tagging: Tagging::Plain { wide },
    });
}

fn extract_utf16le(bytes: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    let mut i: usize = 0;
    let n: usize = bytes.len();
    while i + 1 < n {
        if bytes[i + 1] == 0 && is_strong_printable(bytes[i]) {
            let start: usize = i;
            let mut chars: Vec<u8> = Vec::new();
            while i + 1 < n && bytes[i + 1] == 0 && is_strong_printable(bytes[i]) {
                chars.push(bytes[i]);
                i += 2;
            }
            if chars.len() >= min_len {
                out.push(ExtractedString {
                    value: String::from_utf8_lossy(&chars).into_owned(),
                    offset: start,
                    tagging: Tagging::Plain { wide: true },
                });
            }
        } else {
            i += 1;
        }
    }
}

const DICTIONARY: [&str; 54] = [
    "admin",
    "advapi32",
    "class",
    "cmd",
    "com",
    "config",
    "connect",
    "create",
    "data",
    "dll",
    "error",
    "exe",
    "export",
    "false",
    "file",
    "function",
    "host",
    "http",
    "https",
    "import",
    "kernel32",
    "key",
    "library",
    "load",
    "memory",
    "module",
    "ntdll",
    "null",
    "object",
    "open",
    "password",
    "path",
    "powershell",
    "process",
    "program",
    "read",
    "recv",
    "registry",
    "send",
    "shell",
    "socket",
    "string",
    "system",
    "temp",
    "the",
    "thread",
    "token",
    "true",
    "user",
    "user32",
    "value",
    "windows",
    "write",
    "www",
];

const _: () = assert!(DICTIONARY.len() <= u64::BITS as usize);

fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let printable: usize = bytes.iter().filter(|&&b: &&u8| is_printable(b)).count();
    printable as f64 / bytes.len() as f64
}

enum XorScreen {
    Scan,
    Histogram(Box<[usize; 256]>),
}

impl XorScreen {
    fn for_run(run: &[u8], work: &mut StringsWork) -> Self {
        if run.len() < XOR_HISTOGRAM_MIN_RUN {
            return Self::Scan;
        }
        let mut histogram: Box<[usize; 256]> = Box::new([0; 256]);
        for &b in run {
            histogram[usize::from(b)] += 1;
        }
        work.xor_screen_steps += run.len() as u64;
        Self::Histogram(histogram)
    }

    fn passes(&self, run: &[u8], key: u8, work: &mut StringsWork) -> bool {
        if run.is_empty() {
            return false;
        }
        let len: f64 = run.len() as f64;
        match self {
            Self::Scan => {
                let mut unprintable: usize = 0;
                for &b in run {
                    work.xor_screen_steps += 1;
                    if is_printable(b ^ key) {
                        continue;
                    }
                    unprintable += 1;
                    if ((run.len() - unprintable) as f64 / len) < XOR_MIN_PRINTABLE_RATIO {
                        return false;
                    }
                }
                true
            }
            Self::Histogram(histogram) => {
                work.xor_screen_steps += PRINTABLE_BYTES.len() as u64;
                let printable: usize = PRINTABLE_BYTES
                    .iter()
                    .map(|&p: &u8| histogram[usize::from(p ^ key)])
                    .sum();
                (printable as f64 / len) >= XOR_MIN_PRINTABLE_RATIO
            }
        }
    }
}

const PRINTABLE_BYTES: [u8; 98] = {
    let mut table: [u8; 98] = [0; 98];
    let mut next: usize = 0;
    let mut b: u8 = 0;
    loop {
        if is_printable(b) {
            table[next] = b;
            next += 1;
        }
        if b == u8::MAX {
            break;
        }
        b += 1;
    }
    assert!(next == table.len());
    table
};

fn dict_hits(text: &str) -> usize {
    let bytes: &[u8] = text.as_bytes();
    let mut found: u64 = 0;
    for (start, lead) in bytes.iter().enumerate() {
        let lead: u8 = lead.to_ascii_lowercase();
        let first: usize = DICTIONARY.partition_point(|word: &&str| word.as_bytes()[0] < lead);
        for (index, word) in DICTIONARY.iter().enumerate().skip(first) {
            let word: &[u8] = word.as_bytes();
            if word[0] != lead {
                break;
            }
            if bytes
                .get(start..start + word.len())
                .is_some_and(|window: &[u8]| window.eq_ignore_ascii_case(word))
            {
                found |= 1 << index;
            }
        }
    }
    found.count_ones() as usize
}

fn xor_runs(bytes: &[u8], min_len: usize) -> Vec<(usize, usize)> {
    let floor: usize = min_len.max(XOR_MIN_RUN_LEN);
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = 0;
    let n: usize = bytes.len();
    while i < n {
        if bytes[i] == 0 {
            i += 1;
            continue;
        }
        let start: usize = i;
        while i < n && bytes[i] != 0 {
            i += 1;
        }
        if i - start >= floor {
            runs.push((start, i));
        }
    }
    runs
}

fn brute_xor(bytes: &[u8], min_len: usize, out: &mut Vec<ExtractedString>, work: &mut StringsWork) {
    let floor: usize = min_len.max(XOR_MIN_RUN_LEN);
    for (start, end) in xor_runs(bytes, min_len) {
        let run: &[u8] = &bytes[start..end];
        let screen: XorScreen = XorScreen::for_run(run, work);
        for key in 1u8..=255 {
            if !screen.passes(run, key, work) {
                continue;
            }
            let decoded: Vec<u8> = run.iter().map(|&b: &u8| b ^ key).collect();
            let text: String = String::from_utf8_lossy(&decoded).into_owned();
            let trimmed: &str = text.trim();
            if trimmed.chars().count() < floor {
                continue;
            }
            if dict_hits(trimmed) >= XOR_MIN_DICT_HITS {
                out.push(ExtractedString {
                    value: trimmed.to_owned(),
                    offset: start,
                    tagging: Tagging::Xor { key },
                });
            }
        }
    }
}

fn try_rot(text: &str, n: u8) -> String {
    text.chars()
        .map(|c: char| match c {
            'a'..='z' => (((c as u8 - b'a' + n) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + n) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

fn recover_rot(plain: &[ExtractedString], out: &mut Vec<ExtractedString>) {
    for s in plain {
        if !matches!(s.tagging, Tagging::Plain { .. }) {
            continue;
        }
        if dict_hits(&s.value) >= 1 {
            continue;
        }
        for n in [13u8, 1, 3, 5, 7, 11, 17, 19, 23, 25] {
            let rotated: String = try_rot(&s.value, n);
            if dict_hits(&rotated) >= XOR_MIN_DICT_HITS {
                out.push(ExtractedString {
                    value: rotated,
                    offset: s.offset,
                    tagging: Tagging::Rot { n },
                });
                break;
            }
        }
    }
}

fn recover_base64(plain: &[ExtractedString], out: &mut Vec<ExtractedString>) {
    for s in plain {
        if !matches!(s.tagging, Tagging::Plain { .. }) {
            continue;
        }
        let candidate: &str = s.value.trim();
        if candidate.len() < 8 || candidate.len() > MAX_DECODE_RECURSE_LEN {
            continue;
        }
        if !candidate
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            continue;
        }
        let unpadded: &str = candidate.trim_end_matches('=');
        let Ok(decoded): Result<Vec<u8>, _> = B64_NO_PAD
            .decode(unpadded)
            .or_else(|_| B64_STANDARD.decode(candidate))
        else {
            continue;
        };
        if printable_ratio(&decoded) < XOR_MIN_PRINTABLE_RATIO {
            continue;
        }
        let text: String = String::from_utf8_lossy(&decoded).into_owned();
        if text.chars().filter(|c: &char| !c.is_whitespace()).count() < 4 {
            continue;
        }
        out.push(ExtractedString {
            value: text.trim().to_owned(),
            offset: s.offset,
            tagging: Tagging::Base64,
        });
    }
}

fn recover_codec(plain: &[ExtractedString], out: &mut Vec<ExtractedString>) {
    use crate::codec::{CascadeHit, blind_cascade};
    for s in plain {
        if !matches!(s.tagging, Tagging::Plain { .. }) {
            continue;
        }
        let candidate: &str = s.value.trim();
        if candidate.len() < 8 || candidate.len() > MAX_DECODE_RECURSE_LEN {
            continue;
        }
        for hit in blind_cascade(candidate.as_bytes()) {
            let CascadeHit {
                scheme, decoded, ..
            } = hit;
            let text: String = String::from_utf8_lossy(&decoded).trim().to_owned();
            if text.chars().filter(|c: &char| !c.is_whitespace()).count() < 4 {
                continue;
            }
            out.push(ExtractedString {
                value: text,
                offset: s.offset,
                tagging: Tagging::Codec {
                    scheme: scheme.label().to_owned(),
                },
            });
        }
    }
}

fn recover_stack_strings(bytes: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    let mut i: usize = 0;
    let n: usize = bytes.len();
    while i < n {
        if !is_strong_printable(bytes[i]) {
            i += 1;
            continue;
        }
        let start: usize = i;
        let mut chars: Vec<u8> = Vec::new();
        let mut fillers: usize = 0;
        let mut j: usize = i;
        while j < n {
            if is_strong_printable(bytes[j]) {
                chars.push(bytes[j]);
                j += 1;
            } else if bytes[j] == 0 && j + 1 < n && is_strong_printable(bytes[j + 1]) {
                fillers += 1;
                j += 1;
            } else {
                break;
            }
        }
        let dense_interleave: bool = fillers * 4 >= chars.len();
        if chars.len() >= min_len && dense_interleave {
            let value: String = String::from_utf8_lossy(&chars).into_owned();
            if dict_hits(&value) >= 1 {
                out.push(ExtractedString {
                    value,
                    offset: start,
                    tagging: Tagging::StackString,
                });
            }
        }
        i = j.max(start + 1);
    }
}

fn dedup(mut strings: Vec<ExtractedString>) -> Vec<ExtractedString> {
    strings.sort_by(|a: &ExtractedString, b: &ExtractedString| {
        a.value
            .cmp(&b.value)
            .then_with(|| a.tagging.label().cmp(&b.tagging.label()))
            .then_with(|| a.offset.cmp(&b.offset))
    });
    strings.dedup_by(|a: &mut ExtractedString, b: &mut ExtractedString| {
        a.value == b.value && a.tagging == b.tagging
    });
    strings.sort_by(|a: &ExtractedString, b: &ExtractedString| {
        a.offset.cmp(&b.offset).then_with(|| a.value.cmp(&b.value))
    });
    strings
}

#[must_use]
pub fn extract(bytes: &[u8], opts: Options) -> Vec<ExtractedString> {
    extract_with_work(bytes, opts).0
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StringsWork {
    pub xor_screen_steps: u64,
}

#[must_use]
pub fn extract_with_work(bytes: &[u8], opts: Options) -> (Vec<ExtractedString>, StringsWork) {
    let min_len: usize = opts.min_len.max(1);
    let mut work: StringsWork = StringsWork::default();
    let mut plain: Vec<ExtractedString> = Vec::new();
    extract_ascii(bytes, min_len, &mut plain);
    extract_utf16le(bytes, min_len, &mut plain);

    let mut out: Vec<ExtractedString> = plain.clone();
    if opts.decode {
        brute_xor(bytes, min_len, &mut out, &mut work);
        recover_base64(&plain, &mut out);
        recover_rot(&plain, &mut out);
        recover_codec(&plain, &mut out);
        recover_stack_strings(bytes, min_len, &mut out);
    }
    (dedup(out), work)
}

#[must_use]
pub fn report(bytes: &[u8], uri: Option<&str>, opts: Options) -> StringsReport {
    let strings: Vec<ExtractedString> = extract(bytes, opts);
    StringsReport {
        schema: STRINGS_SCHEMA,
        uri: uri.map(str::to_owned),
        byte_len: bytes.len(),
        min_len: opts.min_len,
        total: strings.len(),
        strings,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_run_padded_with_line_breaks_reports_the_offset_of_its_first_kept_byte() {
        let bytes: &[u8] = b"\x00\r\n\thello strings world\r\n\x00";
        let found: Vec<ExtractedString> = extract(
            bytes,
            Options {
                min_len: 4,
                decode: false,
            },
        );
        let plain: &ExtractedString = found
            .iter()
            .find(|s: &&ExtractedString| s.value == "hello strings world")
            .expect("the run is extracted");
        assert_eq!(plain.offset, 4);
        assert_eq!(
            &bytes[plain.offset..plain.offset + plain.value.len()],
            plain.value.as_bytes()
        );
    }

    #[test]
    fn head_clamps_to_char_boundary_and_never_panics() {
        assert_eq!(head("abc\u{e9}", 4), "abc");
        assert_eq!(head("abc\u{e9}", 100), "abc\u{e9}");
        assert_eq!(head("abc\u{e9}", 0), "");
        let wide: String = "\u{20ac}".repeat(2000);
        let h: &str = head(&wide, 4096);
        assert!(h.len() <= 4096 && wide.is_char_boundary(h.len()));
    }

    fn values(strings: &[ExtractedString]) -> Vec<&str> {
        strings
            .iter()
            .map(|s: &ExtractedString| s.value.as_str())
            .collect()
    }

    #[test]
    fn extracts_plain_ascii_above_min_len() {
        let input: &[u8] = b"\x00\x01hello world\x00\x02hi";
        let strings: Vec<ExtractedString> = extract(input, Options::default());
        assert!(values(&strings).contains(&"hello world"));
        assert!(!values(&strings).contains(&"hi"));
    }

    #[test]
    fn extracts_utf16le_wide_string() {
        let mut input: Vec<u8> = Vec::new();
        for c in "WideKernel".bytes() {
            input.push(c);
            input.push(0);
        }
        let strings: Vec<ExtractedString> = extract(&input, Options::default());
        let wide: Option<&ExtractedString> = strings
            .iter()
            .find(|s: &&ExtractedString| matches!(s.tagging, Tagging::Plain { wide: true }));
        assert!(wide.is_some(), "{strings:?}");
        assert_eq!(wide.expect("wide present").value, "WideKernel");
    }

    #[test]
    fn min_len_is_respected() {
        let input: &[u8] = b"abcdefghij";
        let opts: Options = Options {
            min_len: 12,
            decode: false,
        };
        let strings: Vec<ExtractedString> = extract(input, opts);
        assert!(strings.is_empty(), "{strings:?}");
    }

    #[test]
    fn recovers_single_byte_xor() {
        let plaintext: &[u8] = b"https://kernel32.dll/connect/process";
        let key: u8 = 0x5a;
        let encoded: Vec<u8> = plaintext.iter().map(|&b: &u8| b ^ key).collect();
        let strings: Vec<ExtractedString> = extract(&encoded, Options::default());
        let recovered: Option<&ExtractedString> = strings
            .iter()
            .find(|s: &&ExtractedString| matches!(s.tagging, Tagging::Xor { key: k } if k == key));
        assert!(recovered.is_some(), "xor not recovered: {strings:?}");
        assert!(
            recovered
                .expect("recovered present")
                .value
                .contains("kernel32")
        );
    }

    #[test]
    fn recovers_base64_payload() {
        let inner: &str = "powershell -enc download";
        let encoded: String = B64_STANDARD.encode(inner);
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"\x00\x00");
        input.extend_from_slice(encoded.as_bytes());
        input.extend_from_slice(b"\x00\x00");
        let strings: Vec<ExtractedString> = extract(&input, Options::default());
        let decoded: Option<&ExtractedString> = strings
            .iter()
            .find(|s: &&ExtractedString| s.tagging == Tagging::Base64);
        assert!(decoded.is_some(), "base64 not recovered: {strings:?}");
        assert_eq!(decoded.expect("decoded present").value, inner);
    }

    #[test]
    fn recovers_rot13() {
        let plaintext: &str = "https kernel system process";
        let rot13: String = try_rot(plaintext, 13);
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"\x00");
        input.extend_from_slice(rot13.as_bytes());
        input.extend_from_slice(b"\x00");
        let strings: Vec<ExtractedString> = extract(&input, Options::default());
        let recovered: Option<&ExtractedString> = strings
            .iter()
            .find(|s: &&ExtractedString| matches!(s.tagging, Tagging::Rot { n: 13 }));
        assert!(recovered.is_some(), "rot13 not recovered: {strings:?}");
        assert_eq!(recovered.expect("present").value, plaintext);
    }

    #[test]
    fn recovers_stack_string() {
        let input: &[u8] = b"k\x00e\x00r\x00n\x00e\x00l\x003\x002\x00";
        let strings: Vec<ExtractedString> = extract(input, Options::default());
        assert!(
            strings
                .iter()
                .any(|s: &ExtractedString| s.value.contains("kernel")),
            "{strings:?}"
        );
    }

    #[test]
    fn decode_disabled_only_yields_plain() {
        let key: u8 = 0x33;
        let encoded: Vec<u8> = b"https://system/process/kernel"
            .iter()
            .map(|&b: &u8| b ^ key)
            .collect();
        let opts: Options = Options {
            min_len: 4,
            decode: false,
        };
        let strings: Vec<ExtractedString> = extract(&encoded, opts);
        assert!(
            strings
                .iter()
                .all(|s: &ExtractedString| matches!(s.tagging, Tagging::Plain { .. })),
            "{strings:?}"
        );
    }

    #[test]
    fn dedup_collapses_identical_tagged_strings() {
        let input: &[u8] = b"alpha\x00alpha\x00alpha";
        let strings: Vec<ExtractedString> = extract(input, Options::default());
        let alphas: usize = strings
            .iter()
            .filter(|s: &&ExtractedString| {
                s.value == "alpha" && matches!(s.tagging, Tagging::Plain { wide: false })
            })
            .count();
        assert_eq!(alphas, 1, "{strings:?}");
    }

    #[test]
    fn tagging_labels_are_stable() {
        assert_eq!(Tagging::Plain { wide: false }.label(), "plain");
        assert_eq!(Tagging::Plain { wide: true }.label(), "plain:wide");
        assert_eq!(Tagging::Xor { key: 0x5a }.label(), "xor:0x5a");
        assert_eq!(Tagging::Base64.label(), "base64");
        assert_eq!(Tagging::Rot { n: 13 }.label(), "rot:13");
        assert_eq!(Tagging::StackString.label(), "stack-string");
        assert_eq!(
            Tagging::Codec {
                scheme: "base91".to_owned()
            }
            .label(),
            "codec:base91"
        );
    }

    #[test]
    fn recovers_base91_via_codec_cascade() {
        let inner: &str = "https://drop.example.com/stage powershell download config";
        let encoded: String = crate::codec::alphabets::base91_encode(inner.as_bytes());
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"\x00\x00");
        input.extend_from_slice(encoded.as_bytes());
        input.extend_from_slice(b"\x00\x00");
        let strings: Vec<ExtractedString> = extract(&input, Options::default());
        let recovered: Option<&ExtractedString> = strings.iter().find(|s: &&ExtractedString| {
            matches!(&s.tagging, Tagging::Codec { scheme } if scheme == "base91")
        });
        assert!(recovered.is_some(), "base91 not recovered: {strings:?}");
        assert!(recovered.expect("present").value.contains("powershell"));
    }

    #[test]
    fn report_serializes_with_schema_and_flattened_tag() {
        let report: StringsReport = report(
            b"\x00hello world kernel\x00",
            Some("a.bin"),
            Options::default(),
        );
        let value: serde_json::Value = serde_json::to_value(&report).expect("serialize");
        assert_eq!(value["schema"], serde_json::json!(STRINGS_SCHEMA));
        assert!(value["total"].as_u64().expect("total") >= 1);
        let first: &serde_json::Value = &value["strings"][0];
        assert!(first["tag"].is_string(), "flattened tag missing: {first}");
        let back: Vec<ExtractedString> =
            serde_json::from_value(value["strings"].clone()).expect("round-trip strings");
        assert_eq!(back, report.strings);
    }

    fn reference_dict_hits(text: &str) -> usize {
        let lower: String = text.to_ascii_lowercase();
        DICTIONARY
            .iter()
            .filter(|word: &&&str| lower.contains(**word))
            .count()
    }

    fn reference_brute_xor(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
        let floor: usize = min_len.max(XOR_MIN_RUN_LEN);
        let mut out: Vec<ExtractedString> = Vec::new();
        for (start, end) in xor_runs(bytes, min_len) {
            for key in 1u8..=255 {
                let decoded: Vec<u8> = bytes[start..end].iter().map(|&b: &u8| b ^ key).collect();
                if printable_ratio(&decoded) < XOR_MIN_PRINTABLE_RATIO {
                    continue;
                }
                let text: String = String::from_utf8_lossy(&decoded).into_owned();
                let trimmed: &str = text.trim();
                if trimmed.chars().count() < floor
                    || reference_dict_hits(trimmed) < XOR_MIN_DICT_HITS
                {
                    continue;
                }
                out.push(ExtractedString {
                    value: trimmed.to_owned(),
                    offset: start,
                    tagging: Tagging::Xor { key },
                });
            }
        }
        out
    }

    fn xor_with(text: &[u8], key: u8) -> Vec<u8> {
        text.iter().map(|&b: &u8| b ^ key).collect()
    }

    fn xor_screen_corpus() -> Vec<u8> {
        use rand::RngExt;
        let sentence: &[u8] =
            b"Open the Registry key, then CreateProcess with the user password token. ";
        let mut corpus: Vec<u8> = Vec::new();
        let mut rng: crate::rng::SeededRng = crate::rng::seeded(0x5eed);
        for _ in 0..64 {
            let len: usize = rng.random_range(1..3000);
            corpus.extend((0..len).map(|_| rng.random::<u8>()));
        }
        for key in [0x01u8, 0x20, 0x41, 0x5a, 0x7f, 0xaa, 0xff] {
            corpus.push(0);
            corpus.extend(xor_with(sentence, key));
            corpus.push(0);
            corpus.extend(xor_with(&sentence.repeat(30), key));
        }
        for (fill, len) in [(0xccu8, 900usize), (0xff, 1023), (0xff, 1024), (0x41, 4000)] {
            corpus.push(0);
            corpus.extend(std::iter::repeat_n(fill, len));
        }
        for (len, unprintable) in [(100usize, 5usize), (100, 6), (2000, 100), (2000, 101)] {
            let mut run: Vec<u8> = sentence.iter().copied().cycle().take(len).collect();
            for slot in run.iter_mut().step_by(len / unprintable).take(unprintable) {
                *slot = 0x80;
            }
            corpus.push(0);
            corpus.extend(xor_with(&run, 0x5a));
        }
        corpus.push(0);
        corpus
    }

    #[test]
    fn xor_screen_keeps_every_string_the_full_decode_finds() {
        let corpus: Vec<u8> = xor_screen_corpus();
        let mut found: Vec<ExtractedString> = Vec::new();
        let mut work: StringsWork = StringsWork::default();
        brute_xor(&corpus, 4, &mut found, &mut work);
        let reference: Vec<ExtractedString> = reference_brute_xor(&corpus, 4);
        for histogram in [false, true] {
            assert!(
                reference.iter().any(|s: &ExtractedString| (s.value.len()
                    >= XOR_HISTOGRAM_MIN_RUN)
                    == histogram),
                "the corpus must decode runs on both sides of the histogram threshold"
            );
        }
        let at_the_printable_floor: usize = reference
            .iter()
            .filter(|s: &&ExtractedString| {
                s.tagging == Tagging::Xor { key: 0x5a } && s.value.contains('\u{fffd}')
            })
            .count();
        assert_eq!(
            at_the_printable_floor, 2,
            "exactly the two runs at 95% printable decode, one per screen"
        );
        assert_eq!(found, reference);
    }

    #[test]
    fn dictionary_hits_match_the_lowercase_substring_count() {
        assert!(DICTIONARY.is_sorted());
        let every_word: String = DICTIONARY.join(" ").to_ascii_uppercase();
        for text in [
            "",
            "https://www.example.com/the/path",
            "HTTPS KERNEL32 Advapi32 NtDll",
            "usersuser32",
            "keykeykey",
            "caf\u{e9} Shell \u{20ac} socket",
            "thethethe",
            "Powershell -c read write",
            every_word.as_str(),
        ] {
            assert_eq!(dict_hits(text), reference_dict_hits(text), "{text:?}");
        }
        assert_eq!(dict_hits(&every_word), DICTIONARY.len());
    }

    #[test]
    fn xor_screen_work_stays_linear_in_the_input() {
        use rand::RngExt;
        let mut rng: crate::rng::SeededRng = crate::rng::seeded(7);
        let one_run: Vec<u8> = (0..1 << 20)
            .map(|_| rng.random_range(1..=u8::MAX))
            .collect();
        let short_runs: Vec<u8> = one_run
            .iter()
            .enumerate()
            .map(|(index, &b): (usize, &u8)| if index % 300 == 0 { 0 } else { b })
            .collect();
        for (label, input) in [("one run", one_run), ("300-byte runs", short_runs)] {
            let (_, work): (Vec<ExtractedString>, StringsWork) =
                extract_with_work(&input, Options::default());
            let bound: u64 = 64 * input.len() as u64;
            assert!(
                work.xor_screen_steps <= bound,
                "{label}: xor screening must not decode each run once per key: {work:?}, bound {bound}"
            );
        }
    }
}
