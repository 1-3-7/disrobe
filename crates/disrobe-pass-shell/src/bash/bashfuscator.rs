use std::io::Read;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use flate2::read::GzDecoder;
use regex::Regex;
use serde::Serialize;

use crate::error::Result;

use super::indirect::{IndirectionReport, peel_indirection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BashfuscatorLevel {
    Token,
    String,
    Obfuscate,
    Compress,
}

#[derive(Debug, Clone, Serialize)]
pub struct BashfuscatorReport {
    pub level: BashfuscatorLevel,
    pub steps: Vec<String>,
    pub walls: Vec<String>,
    pub output: String,
}

const MAX_PEEL_ROUNDS: usize = 12;
const MAX_DECOMPRESS_BYTES: usize = 8 * 1024 * 1024;
const MAX_BASE64_INPUT: usize = 2 * 1024 * 1024;

pub fn reverse_bashfuscator(level: BashfuscatorLevel, input: &str) -> Result<BashfuscatorReport> {
    let mut steps: Vec<String> = Vec::new();
    let mut walls: Vec<String> = Vec::new();
    let mut current: String = input.to_owned();
    let mut swapcase_used: bool = false;
    for round in 0..MAX_PEEL_ROUNDS {
        let before: String = current.clone();
        current = strip_shebang(&current, &mut steps);
        if !swapcase_used && let Some(unwrapped) = try_obfuscate_swapcase(&current, &mut steps) {
            current = unwrapped;
            swapcase_used = true;
            continue;
        }
        current = strip_noise_expansions(&current, &mut steps);
        current = decode_ansi_c_quoting(&current, &mut steps);
        current = strip_unquoted_backslashes(&current, &mut steps);
        current = concat_adjacent_strings(&current, &mut steps);
        current = evaluate_arithmetic(&current, &mut steps);
        current = collapse_adjacent_word_runs(&current, &mut steps);
        if !swapcase_used && let Some(unwrapped) = try_obfuscate_swapcase(&current, &mut steps) {
            current = unwrapped;
            swapcase_used = true;
            continue;
        }
        if let Some(unwrapped) = try_compress_payload(&current, &mut steps)? {
            current = unwrapped;
            continue;
        }
        if let Some(unwrapped) = try_printf_substitution_wrap(&current, &mut steps) {
            current = unwrapped;
            continue;
        }
        if let Some(unwrapped) = try_eval_wrap(&current, &mut steps) {
            current = unwrapped;
            continue;
        }
        if current == before {
            break;
        }
        if round == MAX_PEEL_ROUNDS - 1 {
            walls.push("max-peel-rounds-reached".to_owned());
        }
    }
    let indirection: IndirectionReport = peel_indirection(&current)?;
    if !indirection.steps.is_empty() {
        steps.extend(indirection.steps);
        current = indirection.output;
    }
    if level == BashfuscatorLevel::Token
        && let Some(lookup) = super::bash_eval::try_token_array_lookup(&current)
    {
        steps.push(format!(
            "eval-token-array-lookup:elements={},indices={}",
            lookup.elements.len(),
            lookup.indices.len()
        ));
        current = lookup.output;
    } else if level == BashfuscatorLevel::Token && current_still_has_token_lookup(&current) {
        walls.push(
            "token-array-lookup: structure detected but bounded-eval could not parse array+for body"
                .to_owned(),
        );
    }
    if level == BashfuscatorLevel::String
        && let Some(decoded) = super::bash_eval::try_string_split_indirection(&current)
    {
        steps.push(format!(
            "eval-string-split-indirection:bytes={}",
            decoded.bytes_emitted
        ));
        current = decoded.output;
    } else if level == BashfuscatorLevel::String && current_still_has_string_split(&current) {
        walls.push(
            "string-split: structure detected but bounded-eval could not resolve all md5/cut chunks"
                .to_owned(),
        );
    }
    Ok(BashfuscatorReport {
        level,
        steps,
        walls,
        output: restore_ansi_c_sentinels(&current),
    })
}

pub fn reverse_bashfuscator_auto(input: &str) -> Result<BashfuscatorReport> {
    const LEVELS: [BashfuscatorLevel; 3] = [
        BashfuscatorLevel::Token,
        BashfuscatorLevel::String,
        BashfuscatorLevel::Obfuscate,
    ];
    let mut best: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, input)?;
    for level in LEVELS {
        let report: BashfuscatorReport = reverse_bashfuscator(level, input)?;
        if recovery_rank(&report) < recovery_rank(&best) {
            best = report;
        }
    }
    Ok(best)
}

fn recovery_rank(report: &BashfuscatorReport) -> (usize, usize) {
    let residual_soup: usize = report.output.matches("${@").count()
        + report.output.matches("${*").count()
        + report.output.matches("$'\\").count();
    (residual_soup, report.output.trim().len())
}

fn strip_shebang(s: &str, steps: &mut Vec<String>) -> String {
    if let Some(rest) = s.strip_prefix("#!/bin/bash") {
        steps.push("strip-shebang".to_owned());
        return rest.trim_start_matches(['\n', '\r']).to_owned();
    }
    if let Some(rest) = s.strip_prefix("#!/usr/bin/env bash") {
        steps.push("strip-shebang".to_owned());
        return rest.trim_start_matches(['\n', '\r']).to_owned();
    }
    if let Some(rest) = s.strip_prefix("#!/usr/bin/bash") {
        steps.push("strip-shebang".to_owned());
        return rest.trim_start_matches(['\n', '\r']).to_owned();
    }
    s.to_owned()
}

fn strip_noise_expansions(s: &str, steps: &mut Vec<String>) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    let mut stripped: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'$'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'{'
            && let Some(end) = match_brace_expansion(bytes, i + 1)
        {
            let inner: &str = std::str::from_utf8(&bytes[i + 2..end]).unwrap_or("");
            if is_noise_expansion(inner) {
                stripped += 1;
                i = end + 1;
                continue;
            }
        }
        if bytes[i] == b'$'
            && i + 1 < bytes.len()
            && matches!(bytes[i + 1], b'@' | b'*' | b'#' | b'?' | b'!')
        {
            let next: Option<u8> = bytes.get(i + 2).copied();
            let is_word_continuation: bool = matches!(
                next,
                Some(
                    b' ' | b'\t'
                        | b'\n'
                        | b'\r'
                        | b'|'
                        | b';'
                        | b'&'
                        | b')'
                        | b'}'
                        | b'"'
                        | b'\''
                        | b'('
                        | b'{'
                        | b'<'
                        | b'>'
                )
            ) || next.is_none();
            if is_word_continuation && matches!(bytes[i + 1], b'@' | b'*') {
                stripped += 1;
                i += 2;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    if stripped > 0 {
        steps.push(format!("strip-noise-expansions:{stripped}"));
    }
    String::from_utf8(out).unwrap_or_else(|_: std::string::FromUtf8Error| s.to_owned())
}

fn match_brace_expansion(bytes: &[u8], lbrace_idx: usize) -> Option<usize> {
    let mut depth: usize = 1;
    let mut i: usize = lbrace_idx + 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn is_noise_expansion(inner: &str) -> bool {
    let trimmed: &str = inner.trim_start_matches('!');
    let first: Option<char> = trimmed.chars().next();
    matches!(first, Some('@' | '*' | '#'))
}

fn decode_ansi_c_quoting(s: &str, steps: &mut Vec<String>) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    let mut decoded: usize = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len()
            && bytes[i] == b'$'
            && bytes[i + 1] == b'\''
            && let Some(end_quote) = find_closing_ansi_c_single_quote(bytes, i + 2)
        {
            let inner: &[u8] = &bytes[i + 2..end_quote];
            let decoded_bytes: Vec<u8> = decode_ansi_c_inner(inner);
            for b in &decoded_bytes {
                out.push(whitespace_to_sentinel(*b));
            }
            decoded += 1;
            i = end_quote + 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    if decoded > 0 {
        steps.push(format!("decode-ansi-c-quoting:{decoded}"));
    }
    String::from_utf8(out).unwrap_or_else(|_: std::string::FromUtf8Error| s.to_owned())
}

fn find_closing_single_quote(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_closing_ansi_c_single_quote(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'\'' {
            return Some(i);
        }
        i += 1;
    }
    None
}

const SENTINEL_NEWLINE: u8 = 0x01;
const SENTINEL_TAB: u8 = 0x02;
const SENTINEL_SPACE: u8 = 0x03;
const SENTINEL_CR: u8 = 0x04;

fn whitespace_to_sentinel(b: u8) -> u8 {
    match b {
        b'\n' => SENTINEL_NEWLINE,
        b'\t' => SENTINEL_TAB,
        b' ' => SENTINEL_SPACE,
        b'\r' => SENTINEL_CR,
        other => other,
    }
}

pub(crate) fn restore_ansi_c_sentinels(s: &str) -> String {
    if !s.as_bytes().iter().any(|b: &u8| {
        matches!(
            *b,
            SENTINEL_NEWLINE | SENTINEL_TAB | SENTINEL_SPACE | SENTINEL_CR
        )
    }) {
        return s.to_owned();
    }
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for b in s.as_bytes() {
        out.push(match *b {
            SENTINEL_NEWLINE => b'\n',
            SENTINEL_TAB => b'\t',
            SENTINEL_SPACE => b' ',
            SENTINEL_CR => b'\r',
            other => other,
        });
    }
    String::from_utf8(out).unwrap_or_else(|_: std::string::FromUtf8Error| s.to_owned())
}

fn decode_ansi_c_inner(inner: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(inner.len());
    let mut i: usize = 0;
    while i < inner.len() {
        if inner[i] != b'\\' {
            out.push(inner[i]);
            i += 1;
            continue;
        }
        if i + 1 >= inner.len() {
            out.push(b'\\');
            i += 1;
            continue;
        }
        let next: u8 = inner[i + 1];
        match next {
            b'a' => {
                out.push(0x07);
                i += 2;
            }
            b'b' => {
                out.push(0x08);
                i += 2;
            }
            b'e' | b'E' => {
                out.push(0x1B);
                i += 2;
            }
            b'f' => {
                out.push(0x0C);
                i += 2;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'v' => {
                out.push(0x0B);
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'\'' => {
                out.push(b'\'');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'?' => {
                out.push(b'?');
                i += 2;
            }
            b'x' | b'X' => {
                let hex_end: usize = (i + 4).min(inner.len());
                let hex: &str = std::str::from_utf8(&inner[i + 2..hex_end]).unwrap_or("");
                let take: usize = hex
                    .chars()
                    .take_while(|c: &char| c.is_ascii_hexdigit())
                    .count()
                    .min(2);
                if take == 0 {
                    out.push(b'\\');
                    i += 1;
                    continue;
                }
                let digits: &[u8] = &inner[i + 2..i + 2 + take];
                let Some(val): Option<u8> = parse_escape_u8(digits, 16) else {
                    push_original_escape(&mut out, next, digits);
                    i += 2 + take;
                    continue;
                };
                out.push(val);
                i += 2 + take;
            }
            b'u' => {
                let hex_end: usize = (i + 6).min(inner.len());
                let hex: &str = std::str::from_utf8(&inner[i + 2..hex_end]).unwrap_or("");
                let take: usize = hex
                    .chars()
                    .take_while(|c: &char| c.is_ascii_hexdigit())
                    .count()
                    .min(4);
                if take == 0 {
                    out.push(b'\\');
                    i += 1;
                    continue;
                }
                let digits: &[u8] = &inner[i + 2..i + 2 + take];
                let Some(val): Option<u32> = parse_escape_u32(digits, 16) else {
                    push_original_escape(&mut out, next, digits);
                    i += 2 + take;
                    continue;
                };
                if let Some(c) = char::from_u32(val) {
                    let mut buf: [u8; 4] = [0u8; 4];
                    let encoded: &str = c.encode_utf8(&mut buf);
                    out.extend_from_slice(encoded.as_bytes());
                } else {
                    push_original_escape(&mut out, next, digits);
                }
                i += 2 + take;
            }
            b'U' => {
                let hex_end: usize = (i + 10).min(inner.len());
                let hex: &str = std::str::from_utf8(&inner[i + 2..hex_end]).unwrap_or("");
                let take: usize = hex
                    .chars()
                    .take_while(|c: &char| c.is_ascii_hexdigit())
                    .count()
                    .min(8);
                if take == 0 {
                    out.push(b'\\');
                    i += 1;
                    continue;
                }
                let digits: &[u8] = &inner[i + 2..i + 2 + take];
                let Some(val): Option<u32> = parse_escape_u32(digits, 16) else {
                    push_original_escape(&mut out, next, digits);
                    i += 2 + take;
                    continue;
                };
                if let Some(c) = char::from_u32(val) {
                    let mut buf: [u8; 4] = [0u8; 4];
                    let encoded: &str = c.encode_utf8(&mut buf);
                    out.extend_from_slice(encoded.as_bytes());
                } else {
                    push_original_escape(&mut out, next, digits);
                }
                i += 2 + take;
            }
            c if c.is_ascii_digit() => {
                let max: usize = (i + 4).min(inner.len());
                let oct: &str = std::str::from_utf8(&inner[i + 1..max]).unwrap_or("");
                let take: usize = oct
                    .chars()
                    .take_while(|ch: &char| ('0'..='7').contains(ch))
                    .count()
                    .min(3);
                if take == 0 {
                    out.push(b'\\');
                    i += 1;
                    continue;
                }
                let digits: &[u8] = &inner[i + 1..i + 1 + take];
                let Some(val): Option<u8> = parse_escape_u8(digits, 8) else {
                    out.push(b'\\');
                    out.extend_from_slice(digits);
                    i += 1 + take;
                    continue;
                };
                out.push(val);
                i += 1 + take;
            }
            _ => {
                out.push(next);
                i += 2;
            }
        }
    }
    out
}

fn parse_escape_u8(bytes: &[u8], radix: u32) -> Option<u8> {
    let text: &str = std::str::from_utf8(bytes).ok()?;
    u8::from_str_radix(text, radix).ok()
}

fn parse_escape_u32(bytes: &[u8], radix: u32) -> Option<u32> {
    let text: &str = std::str::from_utf8(bytes).ok()?;
    u32::from_str_radix(text, radix).ok()
}

fn push_original_escape(out: &mut Vec<u8>, prefix: u8, digits: &[u8]) {
    out.push(b'\\');
    out.push(prefix);
    out.extend_from_slice(digits);
}

use super::arith::evaluate_arithmetic;

fn collapse_adjacent_word_runs(s: &str, steps: &mut Vec<String>) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    let mut collapsed: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
            out.push(b);
            i += 1;
            continue;
        }
        if is_word_break(b) {
            out.push(b);
            i += 1;
            continue;
        }
        let mut word_end: usize = i;
        let mut content: Vec<u8> = Vec::new();
        let mut had_quote: bool = false;
        while word_end < bytes.len() && !matches!(bytes[word_end], b' ' | b'\t' | b'\n' | b'\r') {
            let c: u8 = bytes[word_end];
            if is_word_break(c) {
                break;
            }
            if c == b'"' {
                if let Some(end) = find_closing_double_quote(bytes, word_end + 1) {
                    content.extend_from_slice(&bytes[word_end + 1..end]);
                    word_end = end + 1;
                    had_quote = true;
                    continue;
                }
                break;
            }
            if c == b'\'' {
                if let Some(end) = find_closing_single_quote(bytes, word_end + 1) {
                    content.extend_from_slice(&bytes[word_end + 1..end]);
                    word_end = end + 1;
                    had_quote = true;
                    continue;
                }
                break;
            }
            content.push(c);
            word_end += 1;
        }
        if word_end == i {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if had_quote {
            collapsed += 1;
            out.extend_from_slice(&content);
        } else {
            out.extend_from_slice(&bytes[i..word_end]);
        }
        i = word_end;
    }
    if collapsed > 0 {
        steps.push(format!("collapse-word-runs:{collapsed}"));
    }
    String::from_utf8(out).unwrap_or_else(|_: std::string::FromUtf8Error| s.to_owned())
}

fn is_word_break(c: u8) -> bool {
    matches!(
        c,
        b'|' | b'&' | b';' | b'<' | b'>' | b'(' | b')' | b'{' | b'}'
    )
}

fn strip_unquoted_backslashes(s: &str, steps: &mut Vec<String>) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    let mut in_sq: bool = false;
    let mut in_dq: bool = false;
    let mut stripped: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if !in_sq && !in_dq && b == b'\'' {
            in_sq = true;
            out.push(b);
            i += 1;
            continue;
        }
        if in_sq && b == b'\'' {
            in_sq = false;
            out.push(b);
            i += 1;
            continue;
        }
        if !in_sq && !in_dq && b == b'"' {
            in_dq = true;
            out.push(b);
            i += 1;
            continue;
        }
        if in_dq && b == b'"' {
            in_dq = false;
            out.push(b);
            i += 1;
            continue;
        }
        if !in_sq && !in_dq && b == b'\\' && i + 1 < bytes.len() {
            let next: u8 = bytes[i + 1];
            let is_printf_hex_escape: bool = matches!(next, b'x' | b'X');
            if !is_printf_hex_escape && (next.is_ascii_alphabetic() || matches!(next, b'_')) {
                out.push(next);
                stripped += 1;
                i += 2;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    if stripped > 0 {
        steps.push(format!("strip-unquoted-backslashes:{stripped}"));
    }
    String::from_utf8(out).unwrap_or_else(|_: std::string::FromUtf8Error| s.to_owned())
}

fn concat_adjacent_strings(s: &str, steps: &mut Vec<String>) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    let mut joined: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'"' {
            let (segment, next): (Vec<u8>, usize) = collect_adjacent_quoted(bytes, i, b'"');
            if next > i + 1 {
                joined += 1;
                out.push(b'"');
                out.extend_from_slice(&segment);
                out.push(b'"');
                i = next;
                continue;
            }
        }
        if b == b'\'' {
            let (segment, next): (Vec<u8>, usize) = collect_adjacent_quoted(bytes, i, b'\'');
            if next > i + 1 {
                joined += 1;
                out.push(b'\'');
                out.extend_from_slice(&segment);
                out.push(b'\'');
                i = next;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    if joined > 0 {
        steps.push(format!("concat-adjacent-strings:{joined}"));
    }
    String::from_utf8(out).unwrap_or_else(|_: std::string::FromUtf8Error| s.to_owned())
}

fn collect_adjacent_quoted(bytes: &[u8], start: usize, quote: u8) -> (Vec<u8>, usize) {
    let mut out: Vec<u8> = Vec::with_capacity(32);
    let mut i: usize = start;
    let mut any: bool = false;
    while i < bytes.len() && bytes[i] == quote {
        let body_end: Option<usize> = if quote == b'\'' {
            find_closing_single_quote(bytes, i + 1)
        } else {
            find_closing_double_quote(bytes, i + 1)
        };
        let Some(end_idx) = body_end else { break };
        out.extend_from_slice(&bytes[i + 1..end_idx]);
        i = end_idx + 1;
        any = true;
    }
    if !any {
        return (Vec::new(), start);
    }
    (out, i)
}

fn find_closing_double_quote(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            let inner_close: Option<usize> = find_matching_command_subst_close(bytes, i + 2);
            match inner_close {
                Some(end) => {
                    i = end + 1;
                    continue;
                }
                None => return None,
            }
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_matching_command_subst_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: usize = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'\''
            && let Some(end) = find_closing_single_quote(bytes, i + 1)
        {
            i = end + 1;
            continue;
        }
        if bytes[i] == b'"' {
            let mut j: usize = i + 1;
            while j < bytes.len() {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    j += 2;
                    continue;
                }
                if bytes[j] == b'$' && j + 1 < bytes.len() && bytes[j + 1] == b'(' {
                    let inner: Option<usize> = find_matching_command_subst_close(bytes, j + 2);
                    match inner {
                        Some(end) => {
                            j = end + 1;
                            continue;
                        }
                        None => return None,
                    }
                }
                if bytes[j] == b'"' {
                    break;
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            let inner: Option<usize> = find_matching_command_subst_close(bytes, i + 2);
            match inner {
                Some(end) => {
                    i = end + 1;
                    continue;
                }
                None => return None,
            }
        }
        if bytes[i] == b'(' {
            depth += 1;
        } else if bytes[i] == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn try_obfuscate_swapcase(s: &str, steps: &mut Vec<String>) -> Option<String> {
    let var_assign: &Regex = &OBFUSCATE_VAR_ASSIGN_PROBE;
    for cap in var_assign.captures_iter(s) {
        let Some(name_match) = cap.get(1) else {
            continue;
        };
        let var_name: &str = name_match.as_str();
        let value_start: usize = cap.get(0).map_or(0, |m: regex::Match<'_>| m.end());
        let Some(value) = extract_bash_single_quoted_with_escapes(&s[value_start..]) else {
            continue;
        };
        if !has_bashfuscator_swapcase_reference(s, var_name) {
            continue;
        }
        steps.push(format!("obfuscate-swapcase:{var_name}"));
        return Some(swapcase(&value));
    }
    None
}

fn has_bashfuscator_swapcase_reference(s: &str, var_name: &str) -> bool {
    let needle_a: String = format!("\"${{{var_name}~~}}\"");
    if s.contains(&needle_a) {
        return true;
    }
    let needle_b: String = format!("${{{var_name}~~}}");
    let count: usize = s.matches(&needle_b).count();
    count == 1 && s.contains("printf") && s.contains(&format!("{var_name}="))
}

static OBFUSCATE_VAR_ASSIGN_PROBE: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"\b([A-Za-z_][A-Za-z0-9_]*)='"));

fn extract_bash_single_quoted_with_escapes(rest: &str) -> Option<String> {
    let bytes: &[u8] = rest.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if bytes.get(i + 1) == Some(&b'"')
                && bytes.get(i + 2) == Some(&b'\'')
                && bytes.get(i + 3) == Some(&b'"')
                && bytes.get(i + 4) == Some(&b'\'')
            {
                out.push(b'\'');
                i += 5;
                continue;
            }
            return String::from_utf8(out).ok();
        }
        out.push(bytes[i]);
        i += 1;
    }
    None
}

fn swapcase(s: &str) -> String {
    s.chars()
        .map(|c: char| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

fn try_compress_payload(s: &str, steps: &mut Vec<String>) -> Result<Option<String>> {
    let re: &Regex = &COMPRESS_PRINTF_PIPE;
    let Some(cap) = re.captures(s) else {
        return Ok(None);
    };
    let blob: &str = (1..=3)
        .find_map(|i: usize| cap.get(i).map(|m: regex::Match<'_>| m.as_str()))
        .unwrap_or("");
    if blob.is_empty() || blob.len() > MAX_BASE64_INPUT {
        return Ok(None);
    }
    let Ok(raw) = BASE64_STD.decode(blob) else {
        return Ok(None);
    };
    steps.push("compress-base64-decode".to_owned());
    let mut dec: GzDecoder<&[u8]> = GzDecoder::new(&raw[..]);
    let mut out: Vec<u8> = Vec::with_capacity(gzip_output_prealloc(raw.len()));
    let mut buf: [u8; 8192] = [0u8; 8192];
    let mut total: usize = 0;
    loop {
        let n: usize = match dec.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        total += n;
        if total > MAX_DECOMPRESS_BYTES {
            return Ok(None);
        }
        out.extend_from_slice(&buf[..n]);
    }
    steps.push("compress-gzip-inflate".to_owned());
    Ok(Some(String::from_utf8_lossy(&out).into_owned()))
}

const fn gzip_output_prealloc(compressed_len: usize) -> usize {
    let capped: usize = compressed_len.saturating_mul(4);
    if capped > MAX_DECOMPRESS_BYTES {
        MAX_DECOMPRESS_BYTES
    } else {
        capped
    }
}

static COMPRESS_PRINTF_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?:printf|echo)\s+(?:'([A-Za-z0-9+/=]+)'|"([A-Za-z0-9+/=]+)"|([A-Za-z0-9+/=]+))\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:gzip|gunzip|zcat)\s*-c?"#,
    )
});

fn try_printf_substitution_wrap(s: &str, steps: &mut Vec<String>) -> Option<String> {
    let trimmed: &str = s.trim();
    let after_prefix: &str = trimmed.strip_prefix("printf")?;
    let after_ws: &str = after_prefix.trim_start();
    let after_fmt: &str = after_ws.strip_prefix("%s")?.trim_start();
    let after_open: &str = after_fmt.strip_prefix("\"$(")?;
    let body_end: usize = find_matching_substitution_close(after_open)?;
    steps.push("unwrap-printf-substitution".to_owned());
    Some(after_open[..body_end].to_owned())
}

fn find_matching_substitution_close(s: &str) -> Option<usize> {
    let bytes: &[u8] = s.as_bytes();
    let mut depth: usize = 1;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn try_eval_wrap(s: &str, steps: &mut Vec<String>) -> Option<String> {
    let trimmed: &str = s.trim();
    let after_prefix: &str = trimmed.strip_prefix("eval")?;
    let after_ws: &str = after_prefix.trim_start();
    let after_open: &str = after_ws.strip_prefix("\"$(")?;
    let body_end: usize = find_matching_substitution_close(after_open)?;
    steps.push("unwrap-eval-substitution".to_owned());
    Some(after_open[..body_end].to_owned())
}

fn current_still_has_token_lookup(s: &str) -> bool {
    s.contains("for ") && s.contains("[ $") && s.contains("printf %s")
}

fn current_still_has_string_split(s: &str) -> bool {
    s.matches("printf").count() >= 4 && s.contains("md5sum") && s.contains("cut -b")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverses_token_level_base64_pipe() -> Result<()> {
        let payload: &str = "id";
        let b64: String = BASE64_STD.encode(payload);
        let src: String = format!("echo '{b64}' | base64 -d");
        let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Token, &src)?;
        assert!(r.output.contains(payload), "got: {}", r.output);
        Ok(())
    }

    #[test]
    fn obfuscate_recovers_payload_from_swapcase() -> Result<()> {
        let src: &str = r#"${@,,} ${*~~} eval "$(    SECRET='ECHO HELLO WORLD' && printf %s "${SECRET~~}"  )" ${*}"#;
        let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, src)?;
        assert!(r.output.contains("echo hello world"), "got: {}", r.output);
        assert!(
            r.steps
                .iter()
                .any(|s: &String| s.starts_with("obfuscate-swapcase"))
        );
        Ok(())
    }

    #[test]
    fn compress_recovers_payload_through_gzip() -> Result<()> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let payload: &str = "echo compressed-payload-detected";
        let mut gz: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(payload.as_bytes())?;
        let raw: Vec<u8> = gz.finish()?;
        let b64: String = BASE64_STD.encode(&raw);
        let src: String =
            format!("${{@,,}} eval \"$( printf '{b64}' | base64 -d | gunzip -c )\" ${{*}}");
        let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, &src)?;
        assert!(
            r.output.contains("compressed-payload-detected"),
            "got: {}",
            r.output
        );
        Ok(())
    }

    #[test]
    fn gzip_prealloc_is_capped_to_decompress_limit() {
        let small: usize = gzip_output_prealloc(8usize);
        let huge: usize = gzip_output_prealloc((MAX_DECOMPRESS_BYTES / 4usize) + 4096usize);
        assert_eq!(small, 32usize);
        assert_eq!(huge, MAX_DECOMPRESS_BYTES);
    }

    #[test]
    fn ansi_c_quoting_decodes_printf() {
        let s: &str = r#"$'\x70'$'\x72'$'\x69'$'\x6e'$'\x74'$'\x66'"#;
        let mut steps: Vec<String> = Vec::new();
        let out: String = decode_ansi_c_quoting(s, &mut steps);
        assert_eq!(out, "printf");
    }

    #[test]
    fn ansi_c_quoting_preserves_invalid_unicode_scalar() {
        let s: &str = r#"$'\U00110000'"#;
        let mut steps: Vec<String> = Vec::new();
        let out: String = decode_ansi_c_quoting(s, &mut steps);
        assert_eq!(out, r#"\U00110000"#);
    }

    #[test]
    fn noise_expansions_are_stripped() {
        let s: &str = r#"${@,,}printf${*~~}%s"hello"${*//foo/bar}"#;
        let mut steps: Vec<String> = Vec::new();
        let out: String = strip_noise_expansions(s, &mut steps);
        assert!(!out.contains("${@"));
        assert!(!out.contains("${*"));
        assert!(out.contains("printf"));
        assert!(out.contains("hello"));
    }

    #[test]
    fn adjacent_strings_collapse() {
        let s: &str = r#""p""r""i""n"'t''f'"#;
        let mut steps: Vec<String> = Vec::new();
        let out: String = concat_adjacent_strings(s, &mut steps);
        assert!(out.contains("\"prin\""));
        assert!(out.contains("'tf'"));
    }

    #[test]
    fn unquoted_backslash_alphabetic_strip() {
        let s: &str = r#"\p\r\i\n\t\f"#;
        let mut steps: Vec<String> = Vec::new();
        let out: String = strip_unquoted_backslashes(s, &mut steps);
        assert_eq!(out, "printf");
    }

    #[test]
    fn auto_recovers_swapcase_payload_without_being_told_the_level() -> Result<()> {
        let src: &str = r#"${@,,} ${*~~} eval "$(    SECRET='ECHO HELLO WORLD' && printf %s "${SECRET~~}"  )" ${*}"#;
        let r: BashfuscatorReport = reverse_bashfuscator_auto(src)?;
        assert!(
            r.output.contains("echo hello world"),
            "auto must pick the obfuscate path and recover the payload; got: {}",
            r.output
        );
        Ok(())
    }

    #[test]
    fn auto_recovers_gzip_payload_without_being_told_the_level() -> Result<()> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let payload: &str = "echo auto-gzip-detected";
        let mut gz: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(payload.as_bytes())?;
        let raw: Vec<u8> = gz.finish()?;
        let b64: String = BASE64_STD.encode(&raw);
        let src: String =
            format!("${{@,,}} eval \"$( printf '{b64}' | base64 -d | gunzip -c )\" ${{*}}");
        let r: BashfuscatorReport = reverse_bashfuscator_auto(&src)?;
        assert!(
            r.output.contains("auto-gzip-detected"),
            "auto must pick the compress path and inflate the gzip payload; got: {}",
            r.output
        );
        Ok(())
    }
}
