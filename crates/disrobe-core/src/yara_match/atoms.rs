use std::collections::BTreeSet;

use regex::bytes::{Regex, RegexBuilder};

use crate::yara::{YaraString, YaraStringKind};

const HEX_WORK_BUDGET: u64 = 1 << 20;
const ATOM_MAX_LEN: usize = 4;
const ATOM_MIN_LEN: usize = 2;

#[derive(Debug)]
pub(super) struct Unsupported {
    pub(super) reason: String,
}

impl Unsupported {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum HexByte {
    Exact(u8),
    Masked { mask: u8, val: u8 },
}

impl HexByte {
    #[inline]
    const fn accepts(self, byte: u8) -> bool {
        match self {
            Self::Exact(want) => byte == want,
            Self::Masked { mask, val } => byte & mask == val,
        }
    }
}

#[derive(Debug, Clone)]
enum HexToken {
    Single(HexByte),
    Jump { min: usize, max: Option<usize> },
    Alt(Vec<Vec<HexByte>>),
}

#[derive(Debug)]
pub(super) struct AtomSpec {
    pub(super) bytes: Vec<u8>,
    pub(super) back: usize,
}

#[derive(Debug, Clone, Copy)]
struct LiteralForms {
    nocase: bool,
    fullword: bool,
    ascii: bool,
    wide: bool,
}

#[derive(Debug)]
enum Matcher {
    Literal {
        needle: Vec<u8>,
        forms: LiteralForms,
    },
    Hex {
        tokens: Vec<HexToken>,
    },
    Regex {
        engine: Box<Regex>,
    },
}

#[derive(Debug)]
pub(super) struct StringProgram {
    pub(super) id: String,
    pub(super) private: bool,
    pub(super) atom: Option<AtomSpec>,
    matcher: Matcher,
}

impl StringProgram {
    pub(super) fn compile(string: &YaraString) -> Result<Self, Unsupported> {
        let private: bool = string.modifiers.iter().any(|m: &String| m == "private");
        match string.kind {
            YaraStringKind::Text => compile_text(string, private),
            YaraStringKind::Hex => compile_hex(string, private),
            YaraStringKind::Regex => compile_regex(string, private),
        }
    }

    pub(super) fn verify_at(&self, buf: &[u8], pos: usize) -> bool {
        match &self.matcher {
            Matcher::Literal { needle, forms } => literal_verify(needle, forms.fullword, buf, pos),
            Matcher::Hex { tokens } => {
                let mut budget: u64 = HEX_WORK_BUDGET;
                hex_matches_at(tokens, 0, buf, pos, &mut budget)
            }
            Matcher::Regex { engine } => buf
                .get(pos..)
                .and_then(|tail: &[u8]| engine.find(tail))
                .is_some_and(|m: regex::bytes::Match<'_>| m.start() == 0 && m.end() > 0),
        }
    }

    pub(super) fn find_all(&self, buf: &[u8]) -> Vec<u64> {
        match &self.matcher {
            Matcher::Literal { needle, forms } => literal_find_all(needle, *forms, buf),
            Matcher::Hex { tokens } => hex_find_all(tokens, buf),
            Matcher::Regex { engine } => regex_find_all(engine, buf),
        }
    }
}

fn compile_text(string: &YaraString, private: bool) -> Result<StringProgram, Unsupported> {
    let mut nocase: bool = false;
    let mut fullword: bool = false;
    let mut has_ascii: bool = false;
    let mut has_wide: bool = false;
    for modifier in &string.modifiers {
        match modifier.as_str() {
            "nocase" => nocase = true,
            "fullword" => fullword = true,
            "ascii" => has_ascii = true,
            "wide" => has_wide = true,
            "private" => {}
            other => {
                return Err(Unsupported::new(format!("text modifier {other:?}")));
            }
        }
    }
    let ascii: bool = has_ascii || !has_wide;
    let wide: bool = has_wide;
    if fullword && wide {
        return Err(Unsupported::new("fullword combined with wide"));
    }
    let needle: Vec<u8> = decode_text(&string.value);
    if needle.is_empty() {
        return Err(Unsupported::new("empty text string"));
    }
    let atom: Option<AtomSpec> = if ascii && !wide && !nocase {
        pick_atom(&needle).map(|(back, bytes): (usize, Vec<u8>)| AtomSpec { bytes, back })
    } else {
        None
    };
    Ok(StringProgram {
        id: string.id.clone(),
        private,
        atom,
        matcher: Matcher::Literal {
            needle,
            forms: LiteralForms {
                nocase,
                fullword,
                ascii,
                wide,
            },
        },
    })
}

fn compile_hex(string: &YaraString, private: bool) -> Result<StringProgram, Unsupported> {
    for modifier in &string.modifiers {
        if modifier != "private" {
            return Err(Unsupported::new(format!("hex modifier {modifier:?}")));
        }
    }
    let tokens: Vec<HexToken> = parse_hex_tokens(&string.value)?;
    if tokens.is_empty() {
        return Err(Unsupported::new("empty hex pattern"));
    }
    let atom: Option<AtomSpec> = hex_atom(&tokens);
    Ok(StringProgram {
        id: string.id.clone(),
        private,
        atom,
        matcher: Matcher::Hex { tokens },
    })
}

fn compile_regex(string: &YaraString, private: bool) -> Result<StringProgram, Unsupported> {
    let mut case_insensitive: bool = false;
    let mut dot_all: bool = false;
    let mut ignore_ws: bool = false;
    let mut multiline: bool = false;
    for modifier in &string.modifiers {
        match modifier.as_str() {
            "i" | "nocase" => case_insensitive = true,
            "s" => dot_all = true,
            "x" => ignore_ws = true,
            "m" => multiline = true,
            "private" => {}
            other => {
                return Err(Unsupported::new(format!("regex modifier {other:?}")));
            }
        }
    }
    if has_anchor_or_boundary(&string.value) {
        return Err(Unsupported::new("regex anchor or word boundary"));
    }
    let engine: Regex = RegexBuilder::new(&string.value)
        .unicode(false)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dot_all)
        .ignore_whitespace(ignore_ws)
        .multi_line(multiline)
        .build()
        .map_err(|e: regex::Error| Unsupported::new(format!("regex compile: {e}")))?;
    Ok(StringProgram {
        id: string.id.clone(),
        private,
        atom: None,
        matcher: Matcher::Regex {
            engine: Box::new(engine),
        },
    })
}

fn has_anchor_or_boundary(pattern: &str) -> bool {
    let bytes: &[u8] = pattern.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if let Some(&next) = bytes.get(i + 1)
                    && (next == b'b' || next == b'B')
                {
                    return true;
                }
                i += 2;
            }
            b'^' | b'$' => return true,
            _ => i += 1,
        }
    }
    false
}

fn decode_text(value: &str) -> Vec<u8> {
    let bytes: &[u8] = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                b'"' => {
                    out.push(b'"');
                    i += 2;
                }
                b'x' if i + 4 <= bytes.len() => {
                    if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                        out.push((hi << 4) | lo);
                        i += 4;
                    } else {
                        out.push(b'\\');
                        i += 1;
                    }
                }
                _ => {
                    out.push(b'\\');
                    i += 1;
                }
            }
        } else {
            out.push(b);
            i += 1;
        }
    }
    out
}

#[inline]
const fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[inline]
const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn fullword_ok(buf: &[u8], start: usize, len: usize) -> bool {
    let before_ok: bool = start == 0 || !is_word_byte(buf[start - 1]);
    let end: usize = start + len;
    let after_ok: bool = end >= buf.len() || !is_word_byte(buf[end]);
    before_ok && after_ok
}

fn literal_verify(needle: &[u8], fullword: bool, buf: &[u8], pos: usize) -> bool {
    match buf.get(pos..pos + needle.len()) {
        Some(slice) if slice == needle => !fullword || fullword_ok(buf, pos, needle.len()),
        _ => false,
    }
}

fn literal_find_all(needle: &[u8], forms: LiteralForms, buf: &[u8]) -> Vec<u64> {
    let mut hits: BTreeSet<u64> = BTreeSet::new();
    if forms.ascii {
        collect_literal_form(buf, needle, forms.nocase, forms.fullword, &mut hits);
    }
    if forms.wide {
        let widened: Vec<u8> = interleave_wide(needle);
        collect_literal_form(buf, &widened, forms.nocase, false, &mut hits);
    }
    hits.into_iter().collect()
}

fn interleave_wide(needle: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(needle.len() * 2);
    for &b in needle {
        out.push(b);
        out.push(0);
    }
    out
}

fn collect_literal_form(
    buf: &[u8],
    pattern: &[u8],
    nocase: bool,
    fullword: bool,
    hits: &mut BTreeSet<u64>,
) {
    if pattern.is_empty() || pattern.len() > buf.len() {
        return;
    }
    let last_start: usize = buf.len() - pattern.len();
    for start in 0..=last_start {
        if matches_at(buf, start, pattern, nocase)
            && (!fullword || fullword_ok(buf, start, pattern.len()))
        {
            hits.insert(start as u64);
        }
    }
}

fn matches_at(buf: &[u8], start: usize, pattern: &[u8], nocase: bool) -> bool {
    pattern.iter().enumerate().all(|(k, &want): (usize, &u8)| {
        buf.get(start + k).is_some_and(|&got: &u8| {
            if nocase {
                got.eq_ignore_ascii_case(&want)
            } else {
                got == want
            }
        })
    })
}

fn regex_find_all(engine: &Regex, buf: &[u8]) -> Vec<u64> {
    let mut hits: Vec<u64> = Vec::new();
    for start in 0..buf.len() {
        let Some(tail): Option<&[u8]> = buf.get(start..) else {
            break;
        };
        if let Some(m) = engine.find(tail)
            && m.start() == 0
            && m.end() > 0
        {
            hits.push(start as u64);
        }
    }
    hits
}

fn hex_find_all(tokens: &[HexToken], buf: &[u8]) -> Vec<u64> {
    let mut hits: Vec<u64> = Vec::new();
    for start in 0..buf.len() {
        let mut budget: u64 = HEX_WORK_BUDGET;
        if hex_matches_at(tokens, 0, buf, start, &mut budget) {
            hits.push(start as u64);
        }
    }
    hits
}

fn hex_matches_at(
    tokens: &[HexToken],
    ti: usize,
    buf: &[u8],
    pos: usize,
    budget: &mut u64,
) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    let Some(token): Option<&HexToken> = tokens.get(ti) else {
        return true;
    };
    match token {
        HexToken::Single(hb) => {
            if buf.get(pos).is_some_and(|&byte: &u8| hb.accepts(byte)) {
                hex_matches_at(tokens, ti + 1, buf, pos + 1, budget)
            } else {
                false
            }
        }
        HexToken::Jump { min, max } => {
            let remaining: usize = buf.len().saturating_sub(pos);
            let hi: usize = max.unwrap_or(remaining).min(remaining);
            if *min > hi {
                return false;
            }
            for jump in *min..=hi {
                if hex_matches_at(tokens, ti + 1, buf, pos + jump, budget) {
                    return true;
                }
            }
            false
        }
        HexToken::Alt(branches) => {
            for branch in branches {
                if branch_matches(branch, buf, pos)
                    && hex_matches_at(tokens, ti + 1, buf, pos + branch.len(), budget)
                {
                    return true;
                }
            }
            false
        }
    }
}

fn branch_matches(branch: &[HexByte], buf: &[u8], pos: usize) -> bool {
    branch.iter().enumerate().all(|(k, hb): (usize, &HexByte)| {
        buf.get(pos + k).is_some_and(|&byte: &u8| hb.accepts(byte))
    })
}

fn pick_atom(bytes: &[u8]) -> Option<(usize, Vec<u8>)> {
    if bytes.len() < ATOM_MIN_LEN {
        return None;
    }
    let window: usize = bytes.len().min(ATOM_MAX_LEN);
    let last_start: usize = bytes.len() - window;
    let mut best_start: usize = 0;
    let mut best_score: usize = 0;
    for start in 0..=last_start {
        let slice: &[u8] = &bytes[start..start + window];
        let score: usize = distinct_bytes(slice);
        if score > best_score {
            best_score = score;
            best_start = start;
        }
    }
    Some((best_start, bytes[best_start..best_start + window].to_vec()))
}

fn distinct_bytes(slice: &[u8]) -> usize {
    let mut seen: [bool; 256] = [false; 256];
    for &b in slice {
        seen[b as usize] = true;
    }
    seen.iter().filter(|&&s: &&bool| s).count()
}

fn hex_atom(tokens: &[HexToken]) -> Option<AtomSpec> {
    let mut offset: usize = 0;
    let mut run_start: usize = 0;
    let mut run: Vec<u8> = Vec::new();
    let mut best_run: Vec<u8> = Vec::new();
    let mut best_back: usize = 0;
    for token in tokens {
        match token {
            HexToken::Single(HexByte::Exact(byte)) => {
                if run.is_empty() {
                    run_start = offset;
                }
                run.push(*byte);
                offset += 1;
            }
            HexToken::Single(HexByte::Masked { .. }) => {
                consider_run(&run, run_start, &mut best_run, &mut best_back);
                run.clear();
                offset += 1;
            }
            HexToken::Jump { .. } | HexToken::Alt(_) => {
                consider_run(&run, run_start, &mut best_run, &mut best_back);
                run.clear();
                break;
            }
        }
    }
    consider_run(&run, run_start, &mut best_run, &mut best_back);
    if best_run.len() < ATOM_MIN_LEN {
        return None;
    }
    let (window_offset, bytes): (usize, Vec<u8>) = pick_atom(&best_run)?;
    Some(AtomSpec {
        bytes,
        back: best_back + window_offset,
    })
}

fn consider_run(run: &[u8], run_start: usize, best_run: &mut Vec<u8>, best_back: &mut usize) {
    if run.len() > best_run.len() {
        *best_run = run.to_vec();
        *best_back = run_start;
    }
}

fn parse_hex_tokens(value: &str) -> Result<Vec<HexToken>, Unsupported> {
    let bytes: &[u8] = value.as_bytes();
    let mut i: usize = 0;
    let mut tokens: Vec<HexToken> = Vec::new();
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'[' => {
                let (token, next): (HexToken, usize) = parse_hex_jump(bytes, i)?;
                tokens.push(token);
                i = next;
            }
            b'(' => {
                let (token, next): (HexToken, usize) = parse_hex_alt(bytes, i)?;
                tokens.push(token);
                i = next;
            }
            c if c.is_ascii_hexdigit() || c == b'?' => {
                let (hb, next): (HexByte, usize) = parse_hex_byte(bytes, i)?;
                tokens.push(HexToken::Single(hb));
                i = next;
            }
            other => {
                return Err(Unsupported::new(format!("hex token {:?}", other as char)));
            }
        }
    }
    Ok(tokens)
}

fn parse_hex_byte(bytes: &[u8], start: usize) -> Result<(HexByte, usize), Unsupported> {
    let hi: u8 = *bytes
        .get(start)
        .ok_or_else(|| Unsupported::new("truncated hex byte"))?;
    let lo: u8 = *bytes
        .get(start + 1)
        .ok_or_else(|| Unsupported::new("odd hex nibble count"))?;
    if !(hi == b'?' || hi.is_ascii_hexdigit()) || !(lo == b'?' || lo.is_ascii_hexdigit()) {
        return Err(Unsupported::new("malformed hex byte"));
    }
    if hi == b'?' && lo == b'?' {
        return Ok((
            HexByte::Masked {
                mask: 0x00,
                val: 0x00,
            },
            start + 2,
        ));
    }
    if hi == b'?' {
        let low: u8 = hex_val(lo).ok_or_else(|| Unsupported::new("bad nibble"))?;
        return Ok((
            HexByte::Masked {
                mask: 0x0F,
                val: low,
            },
            start + 2,
        ));
    }
    if lo == b'?' {
        let high: u8 = hex_val(hi).ok_or_else(|| Unsupported::new("bad nibble"))?;
        return Ok((
            HexByte::Masked {
                mask: 0xF0,
                val: high << 4,
            },
            start + 2,
        ));
    }
    let high: u8 = hex_val(hi).ok_or_else(|| Unsupported::new("bad nibble"))?;
    let low: u8 = hex_val(lo).ok_or_else(|| Unsupported::new("bad nibble"))?;
    Ok((HexByte::Exact((high << 4) | low), start + 2))
}

fn parse_hex_jump(bytes: &[u8], start: usize) -> Result<(HexToken, usize), Unsupported> {
    let mut i: usize = start + 1;
    let mut inner: Vec<u8> = Vec::new();
    while let Some(&c) = bytes.get(i) {
        if c == b']' {
            let min_max: HexToken = parse_jump_body(&inner)?;
            return Ok((min_max, i + 1));
        }
        inner.push(c);
        i += 1;
    }
    Err(Unsupported::new("unterminated hex jump"))
}

fn parse_jump_body(inner: &[u8]) -> Result<HexToken, Unsupported> {
    let text: &str = core::str::from_utf8(inner)
        .map_err(|_e: core::str::Utf8Error| Unsupported::new("jump encoding"))?;
    let trimmed: &str = text.trim();
    if let Some((lo, hi)) = trimmed.split_once('-') {
        let min: usize = parse_jump_number(lo.trim())?;
        let max: Option<usize> = if hi.trim().is_empty() {
            None
        } else {
            Some(parse_jump_number(hi.trim())?)
        };
        if let Some(hi_val) = max
            && hi_val < min
        {
            return Err(Unsupported::new("hex jump max below min"));
        }
        Ok(HexToken::Jump { min, max })
    } else {
        let exact: usize = parse_jump_number(trimmed)?;
        Ok(HexToken::Jump {
            min: exact,
            max: Some(exact),
        })
    }
}

fn parse_jump_number(text: &str) -> Result<usize, Unsupported> {
    if text.is_empty() {
        return Ok(0);
    }
    text.parse::<usize>()
        .map_err(|_e: core::num::ParseIntError| Unsupported::new("hex jump bound"))
}

fn parse_hex_alt(bytes: &[u8], start: usize) -> Result<(HexToken, usize), Unsupported> {
    let mut i: usize = start + 1;
    let mut branches: Vec<Vec<HexByte>> = Vec::new();
    let mut current: Vec<HexByte> = Vec::new();
    loop {
        let Some(&c) = bytes.get(i) else {
            return Err(Unsupported::new("unterminated hex alternation"));
        };
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'|' => {
                branches.push(std::mem::take(&mut current));
                i += 1;
            }
            b')' => {
                branches.push(current);
                let non_empty: bool = branches.iter().all(|b: &Vec<HexByte>| !b.is_empty());
                if !non_empty {
                    return Err(Unsupported::new("empty hex alternation branch"));
                }
                return Ok((HexToken::Alt(branches), i + 1));
            }
            b'(' | b'[' => {
                return Err(Unsupported::new("nested hex alternation"));
            }
            hexish if hexish.is_ascii_hexdigit() || hexish == b'?' => {
                let (hb, next): (HexByte, usize) = parse_hex_byte(bytes, i)?;
                current.push(hb);
                i = next;
            }
            other => {
                return Err(Unsupported::new(format!(
                    "hex alternation token {:?}",
                    other as char
                )));
            }
        }
    }
}
