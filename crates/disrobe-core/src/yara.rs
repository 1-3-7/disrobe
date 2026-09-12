use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const YARA_SCHEMA: &str = "disrobe.yara.ruleset/v0";

pub type Result<T> = core::result::Result<T, YaraParseError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YaraStringKind {
    Text,
    Hex,
    Regex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraString {
    pub id: String,
    pub kind: YaraStringKind,
    pub value: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub modifiers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub modifiers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub meta: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strings: Vec<YaraString>,
    pub condition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraRuleset {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub imports: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub includes: Vec<String>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraLoaderReport {
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub rule_count: usize,
    pub ruleset: YaraRuleset,
}

#[derive(Debug, Error)]
pub enum YaraParseError {
    #[error("DR-YARA-0001: expected 'rule' keyword at byte {offset}, found {found:?}")]
    ExpectedRuleKeyword { offset: usize, found: String },

    #[error("DR-YARA-0002: missing rule name after 'rule' at byte {offset}")]
    MissingRuleName { offset: usize },

    #[error("DR-YARA-0003: invalid identifier {ident:?} at byte {offset}")]
    InvalidIdentifier { ident: String, offset: usize },

    #[error("DR-YARA-0004: unbalanced braces in rule {rule:?} (opened at byte {offset})")]
    UnbalancedBraces { rule: String, offset: usize },

    #[error("DR-YARA-0005: rule {rule:?} has no condition section")]
    MissingCondition { rule: String },

    #[error(
        "DR-YARA-0006: malformed string assignment for {id:?} in rule {rule:?} at byte {offset}"
    )]
    MalformedStringAssignment {
        id: String,
        rule: String,
        offset: usize,
    },

    #[error(
        "DR-YARA-0007: unterminated {kind} for {id:?} in rule {rule:?} (started at byte {offset})"
    )]
    UnterminatedValue {
        kind: &'static str,
        id: String,
        rule: String,
        offset: usize,
    },

    #[error("DR-YARA-0008: malformed meta entry in rule {rule:?} at byte {offset}")]
    MalformedMeta { rule: String, offset: usize },

    #[error("DR-YARA-0009: unexpected end of input (expected {expected})")]
    UnexpectedEof { expected: &'static str },

    #[error("DR-YARA-0010: unknown section {section:?} in rule {rule:?} at byte {offset}")]
    UnknownSection {
        section: String,
        rule: String,
        offset: usize,
    },
}

struct Cursor<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    const fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    #[inline]
    const fn remaining(&self) -> usize {
        self.src.len().saturating_sub(self.pos)
    }

    #[inline]
    const fn at_end(&self) -> bool {
        self.pos >= self.src.len()
    }

    #[inline]
    const fn peek(&self) -> Option<u8> {
        if self.pos < self.src.len() {
            Some(self.src[self.pos])
        } else {
            None
        }
    }

    const fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek_keyword(&self, kw: &str) -> bool {
        let bytes: &[u8] = kw.as_bytes();
        if self.remaining() < bytes.len() {
            return false;
        }
        if &self.src[self.pos..self.pos + bytes.len()] != bytes {
            return false;
        }
        match self.src.get(self.pos + bytes.len()) {
            Some(&next) => !is_ident_byte(next),
            None => true,
        }
    }

    fn take_ident(&mut self) -> Option<&'a str> {
        let start: usize = self.pos;
        match self.peek() {
            Some(b) if b.is_ascii_alphabetic() || b == b'_' => self.pos += 1,
            _ => return None,
        }
        while let Some(b) = self.peek() {
            if is_ident_byte(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        core::str::from_utf8(&self.src[start..self.pos]).ok()
    }

    fn take_string_id(&mut self) -> Option<&'a str> {
        if self.peek() != Some(b'$') {
            return None;
        }
        let start: usize = self.pos;
        self.pos += 1;
        while let Some(b) = self.peek() {
            if is_ident_byte(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        core::str::from_utf8(&self.src[start..self.pos]).ok()
    }
}

#[inline]
const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn strip_comments(src: &str) -> String {
    let bytes: &[u8] = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let n: usize = bytes.len();
    let mut i: usize = 0;
    while i < n {
        let b: u8 = bytes[i];
        match b {
            b'"' => {
                out.push(b);
                i += 1;
                while i < n {
                    let c: u8 = bytes[i];
                    out.push(c);
                    i += 1;
                    if c == b'\\' && i < n {
                        out.push(bytes[i]);
                        i += 1;
                    } else if c == b'"' {
                        break;
                    }
                }
            }
            b'/' if i + 1 < n && bytes[i + 1] == b'/' => {
                while i < n && bytes[i] != b'\n' {
                    out.push(b' ');
                    i += 1;
                }
            }
            b'/' if i + 1 < n && bytes[i + 1] == b'*' => {
                out.push(b' ');
                out.push(b' ');
                i += 2;
                while i < n {
                    if i + 1 < n && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        out.push(b' ');
                        out.push(b' ');
                        i += 2;
                        break;
                    }
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| src.to_owned())
}

fn parse_imports_includes(c: &mut Cursor) -> (Vec<String>, Vec<String>) {
    let mut imports: Vec<String> = Vec::new();
    let mut includes: Vec<String> = Vec::new();
    loop {
        c.skip_ws();
        if c.peek_keyword("import") {
            c.pos += "import".len();
            c.skip_ws();
            if let Some(path) = take_quoted_path(c) {
                imports.push(path);
                continue;
            }
            break;
        }
        if c.peek_keyword("include") {
            c.pos += "include".len();
            c.skip_ws();
            if let Some(path) = take_quoted_path(c) {
                includes.push(path);
                continue;
            }
            break;
        }
        break;
    }
    (imports, includes)
}

fn take_quoted_path(c: &mut Cursor) -> Option<String> {
    if c.peek() != Some(b'"') {
        return None;
    }
    c.pos += 1;
    let start: usize = c.pos;
    while let Some(b) = c.peek() {
        if b == b'"' {
            let value: String = String::from_utf8_lossy(&c.src[start..c.pos]).into_owned();
            c.pos += 1;
            return Some(value);
        }
        c.pos += 1;
    }
    None
}

pub fn parse_ruleset(src: &str) -> Result<YaraRuleset> {
    let stripped: String = strip_comments(src);
    let mut c: Cursor<'_> = Cursor::new(stripped.as_bytes());
    let (imports, includes): (Vec<String>, Vec<String>) = parse_imports_includes(&mut c);
    let mut rules: Vec<Rule> = Vec::new();
    loop {
        c.skip_ws();
        if c.at_end() {
            break;
        }
        let rule: Rule = parse_one_rule(&mut c)?;
        rules.push(rule);
    }
    Ok(YaraRuleset {
        imports,
        includes,
        rules,
    })
}

pub fn parse_rule(src: &str) -> Result<Rule> {
    let stripped: String = strip_comments(src);
    let mut c: Cursor<'_> = Cursor::new(stripped.as_bytes());
    c.skip_ws();
    parse_one_rule(&mut c)
}

pub fn parse_report(src: &str, uri: Option<&str>) -> Result<YaraLoaderReport> {
    let ruleset: YaraRuleset = parse_ruleset(src)?;
    let rule_count: usize = ruleset.rules.len();
    Ok(YaraLoaderReport {
        schema: YARA_SCHEMA,
        uri: uri.map(str::to_owned),
        rule_count,
        ruleset,
    })
}

fn parse_one_rule(c: &mut Cursor) -> Result<Rule> {
    let mut modifiers: Vec<String> = Vec::new();
    loop {
        c.skip_ws();
        if c.peek_keyword("private") {
            c.pos += "private".len();
            modifiers.push("private".to_owned());
        } else if c.peek_keyword("global") {
            c.pos += "global".len();
            modifiers.push("global".to_owned());
        } else {
            break;
        }
    }

    c.skip_ws();
    let kw_offset: usize = c.pos;
    if !c.peek_keyword("rule") {
        let found: String = preview_at(c.src, c.pos);
        return Err(YaraParseError::ExpectedRuleKeyword {
            offset: kw_offset,
            found,
        });
    }
    c.pos += "rule".len();

    c.skip_ws();
    let name_offset: usize = c.pos;
    let Some(name): Option<&str> = c.take_ident() else {
        return Err(YaraParseError::MissingRuleName {
            offset: name_offset,
        });
    };
    let name: String = name.to_owned();

    let mut tags: Vec<String> = Vec::new();
    c.skip_ws();
    if c.peek() == Some(b':') {
        c.pos += 1;
        loop {
            c.skip_ws();
            if c.peek() == Some(b'{') {
                break;
            }
            let tag_offset: usize = c.pos;
            let Some(tag): Option<&str> = c.take_ident() else {
                return Err(YaraParseError::InvalidIdentifier {
                    ident: preview_at(c.src, tag_offset),
                    offset: tag_offset,
                });
            };
            tags.push(tag.to_owned());
        }
    }

    c.skip_ws();
    let brace_offset: usize = c.pos;
    if c.peek() != Some(b'{') {
        return Err(YaraParseError::UnbalancedBraces {
            rule: name.clone(),
            offset: brace_offset,
        });
    }
    c.pos += 1;

    let mut meta: BTreeMap<String, String> = BTreeMap::new();
    let mut strings: Vec<YaraString> = Vec::new();
    let mut condition: Option<String> = None;

    loop {
        c.skip_ws();
        match c.peek() {
            Some(b'}') => {
                c.pos += 1;
                break;
            }
            None => {
                return Err(YaraParseError::UnbalancedBraces {
                    rule: name.clone(),
                    offset: brace_offset,
                });
            }
            _ => {}
        }

        let section_offset: usize = c.pos;
        let Some(section): Option<&str> = c.take_ident() else {
            return Err(YaraParseError::UnknownSection {
                section: preview_at(c.src, section_offset),
                rule: name.clone(),
                offset: section_offset,
            });
        };
        let section: String = section.to_owned();
        c.skip_ws();
        if c.peek() != Some(b':') {
            return Err(YaraParseError::UnknownSection {
                section,
                rule: name.clone(),
                offset: section_offset,
            });
        }
        c.pos += 1;

        match section.as_str() {
            "meta" => {
                meta = parse_meta_section(c, &name)?;
            }
            "strings" => {
                strings = parse_strings_section(c, &name)?;
            }
            "condition" => {
                condition = Some(capture_condition(c, &name, brace_offset)?);
            }
            other => {
                return Err(YaraParseError::UnknownSection {
                    section: other.to_owned(),
                    rule: name.clone(),
                    offset: section_offset,
                });
            }
        }
    }

    let Some(condition): Option<String> = condition else {
        return Err(YaraParseError::MissingCondition { rule: name });
    };

    Ok(Rule {
        name,
        modifiers,
        tags,
        meta,
        strings,
        condition,
    })
}

fn at_section_header(c: &Cursor) -> bool {
    c.peek_keyword("meta")
        || c.peek_keyword("strings")
        || c.peek_keyword("condition")
        || c.peek() == Some(b'}')
}

fn parse_meta_section(c: &mut Cursor, rule: &str) -> Result<BTreeMap<String, String>> {
    let mut meta: BTreeMap<String, String> = BTreeMap::new();
    loop {
        c.skip_ws();
        if at_section_header(c) {
            break;
        }
        let key_offset: usize = c.pos;
        let Some(key): Option<&str> = c.take_ident() else {
            return Err(YaraParseError::MalformedMeta {
                rule: rule.to_owned(),
                offset: key_offset,
            });
        };
        let key: String = key.to_owned();
        c.skip_ws();
        if c.peek() != Some(b'=') {
            return Err(YaraParseError::MalformedMeta {
                rule: rule.to_owned(),
                offset: c.pos,
            });
        }
        c.pos += 1;
        c.skip_ws();
        let value: String = match c.peek() {
            Some(b'"') => {
                let (v, _mods): (String, Vec<String>) = parse_text_string(c, &key, rule, false)?;
                v
            }
            Some(b) if b.is_ascii_digit() || b == b'-' => take_meta_scalar(c),
            Some(_) if c.peek_keyword("true") || c.peek_keyword("false") => take_meta_scalar(c),
            _ => {
                return Err(YaraParseError::MalformedMeta {
                    rule: rule.to_owned(),
                    offset: c.pos,
                });
            }
        };
        meta.insert(key, value);
    }
    Ok(meta)
}

fn take_meta_scalar(c: &mut Cursor) -> String {
    let start: usize = c.pos;
    if c.peek() == Some(b'-') {
        c.pos += 1;
    }
    while let Some(b) = c.peek() {
        if b.is_ascii_alphanumeric() || b == b'_' {
            c.pos += 1;
        } else {
            break;
        }
    }
    String::from_utf8_lossy(&c.src[start..c.pos]).into_owned()
}

fn parse_strings_section(c: &mut Cursor, rule: &str) -> Result<Vec<YaraString>> {
    let mut out: Vec<YaraString> = Vec::new();
    loop {
        c.skip_ws();
        if at_section_header(c) {
            break;
        }
        let id_offset: usize = c.pos;
        let Some(id): Option<&str> = c.take_string_id() else {
            return Err(YaraParseError::MalformedStringAssignment {
                id: preview_at(c.src, id_offset),
                rule: rule.to_owned(),
                offset: id_offset,
            });
        };
        let id: String = id.to_owned();
        c.skip_ws();
        if c.peek() != Some(b'=') {
            return Err(YaraParseError::MalformedStringAssignment {
                id,
                rule: rule.to_owned(),
                offset: c.pos,
            });
        }
        c.pos += 1;
        c.skip_ws();
        let value_offset: usize = c.pos;
        let (kind, value, modifiers): (YaraStringKind, String, Vec<String>) = match c.peek() {
            Some(b'"') => {
                let (v, mods): (String, Vec<String>) = parse_text_string(c, &id, rule, true)?;
                (YaraStringKind::Text, v, mods)
            }
            Some(b'{') => {
                let v: String = parse_hex_string(c, &id, rule)?;
                let mods: Vec<String> = take_modifiers(c);
                (YaraStringKind::Hex, v, mods)
            }
            Some(b'/') => {
                let (v, mods): (String, Vec<String>) = parse_regex_string(c, &id, rule)?;
                (YaraStringKind::Regex, v, mods)
            }
            _ => {
                return Err(YaraParseError::MalformedStringAssignment {
                    id,
                    rule: rule.to_owned(),
                    offset: value_offset,
                });
            }
        };
        out.push(YaraString {
            id,
            kind,
            value,
            modifiers,
        });
    }
    Ok(out)
}

const STRING_MODIFIERS: [&str; 8] = [
    "nocase",
    "wide",
    "ascii",
    "fullword",
    "private",
    "xor",
    "base64",
    "base64wide",
];

fn take_modifiers(c: &mut Cursor) -> Vec<String> {
    let mut mods: Vec<String> = Vec::new();
    loop {
        c.skip_ws();
        let mut matched: bool = false;
        for kw in STRING_MODIFIERS {
            if c.peek_keyword(kw) {
                c.pos += kw.len();
                mods.push(kw.to_owned());
                matched = true;
                break;
            }
        }
        if !matched {
            break;
        }
    }
    mods
}

fn parse_text_string(
    c: &mut Cursor,
    id: &str,
    rule: &str,
    allow_modifiers: bool,
) -> Result<(String, Vec<String>)> {
    let start: usize = c.pos;
    if c.peek() != Some(b'"') {
        return Err(YaraParseError::MalformedStringAssignment {
            id: id.to_owned(),
            rule: rule.to_owned(),
            offset: start,
        });
    }
    c.pos += 1;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match c.peek() {
            None | Some(b'\n') => {
                return Err(YaraParseError::UnterminatedValue {
                    kind: "text string",
                    id: id.to_owned(),
                    rule: rule.to_owned(),
                    offset: start,
                });
            }
            Some(b'"') => {
                c.pos += 1;
                break;
            }
            Some(b'\\') => {
                buf.push(b'\\');
                c.pos += 1;
                if let Some(esc) = c.peek() {
                    buf.push(esc);
                    c.pos += 1;
                }
            }
            Some(b) => {
                buf.push(b);
                c.pos += 1;
            }
        }
    }
    let value: String = String::from_utf8_lossy(&buf).into_owned();
    let modifiers: Vec<String> = if allow_modifiers {
        take_modifiers(c)
    } else {
        Vec::new()
    };
    Ok((value, modifiers))
}

fn parse_hex_string(c: &mut Cursor, id: &str, rule: &str) -> Result<String> {
    let start: usize = c.pos;
    if c.peek() != Some(b'{') {
        return Err(YaraParseError::MalformedStringAssignment {
            id: id.to_owned(),
            rule: rule.to_owned(),
            offset: start,
        });
    }
    c.pos += 1;
    let mut depth: usize = 1;
    let body_start: usize = c.pos;
    while let Some(b) = c.peek() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        c.pos += 1;
    }
    if depth != 0 {
        return Err(YaraParseError::UnterminatedValue {
            kind: "hex string",
            id: id.to_owned(),
            rule: rule.to_owned(),
            offset: start,
        });
    }
    let body: &[u8] = &c.src[body_start..c.pos];
    c.pos += 1;
    validate_hex_body(body, id, rule, start)?;
    let normalized: String = normalize_hex(body);
    Ok(normalized)
}

fn validate_hex_body(body: &[u8], id: &str, rule: &str, offset: usize) -> Result<()> {
    let mut saw_token: bool = false;
    for &b in body {
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => {}
            b'?' | b'[' | b']' | b'(' | b')' | b'|' | b'-' => saw_token = true,
            b if b.is_ascii_hexdigit() => saw_token = true,
            _ => {
                return Err(YaraParseError::UnterminatedValue {
                    kind: "hex string",
                    id: id.to_owned(),
                    rule: rule.to_owned(),
                    offset,
                });
            }
        }
    }
    if !saw_token {
        return Err(YaraParseError::UnterminatedValue {
            kind: "hex string",
            id: id.to_owned(),
            rule: rule.to_owned(),
            offset,
        });
    }
    Ok(())
}

fn normalize_hex(body: &[u8]) -> String {
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(body);
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn parse_regex_string(c: &mut Cursor, id: &str, rule: &str) -> Result<(String, Vec<String>)> {
    let start: usize = c.pos;
    if c.peek() != Some(b'/') {
        return Err(YaraParseError::MalformedStringAssignment {
            id: id.to_owned(),
            rule: rule.to_owned(),
            offset: start,
        });
    }
    c.pos += 1;
    let body_start: usize = c.pos;
    let mut terminated: bool = false;
    while let Some(b) = c.peek() {
        match b {
            b'\n' => break,
            b'\\' => {
                c.pos += 1;
                if c.peek().is_some() {
                    c.pos += 1;
                }
            }
            b'/' => {
                terminated = true;
                break;
            }
            _ => c.pos += 1,
        }
    }
    if !terminated {
        return Err(YaraParseError::UnterminatedValue {
            kind: "regex",
            id: id.to_owned(),
            rule: rule.to_owned(),
            offset: start,
        });
    }
    let value: String = String::from_utf8_lossy(&c.src[body_start..c.pos]).into_owned();
    c.pos += 1;
    let mut flags: Vec<String> = Vec::new();
    while let Some(b) = c.peek() {
        if matches!(b, b'i' | b'm' | b's' | b'x') {
            flags.push((b as char).to_string());
            c.pos += 1;
        } else {
            break;
        }
    }
    let extra: Vec<String> = take_modifiers(c);
    flags.extend(extra);
    Ok((value, flags))
}

fn capture_condition(c: &mut Cursor, rule: &str, rule_brace_offset: usize) -> Result<String> {
    let start: usize = c.pos;
    let mut depth: usize = 0;
    let mut end: usize = c.pos;
    loop {
        match c.peek() {
            None => {
                return Err(YaraParseError::UnbalancedBraces {
                    rule: rule.to_owned(),
                    offset: rule_brace_offset,
                });
            }
            Some(b'"') => {
                c.pos += 1;
                while let Some(b) = c.peek() {
                    c.pos += 1;
                    if b == b'\\' {
                        if c.peek().is_some() {
                            c.pos += 1;
                        }
                    } else if b == b'"' {
                        break;
                    }
                }
                end = c.pos;
            }
            Some(b'{') => {
                depth += 1;
                c.pos += 1;
                end = c.pos;
            }
            Some(b'}') => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                c.pos += 1;
                end = c.pos;
            }
            Some(b) => {
                c.pos += 1;
                if !b.is_ascii_whitespace() {
                    end = c.pos;
                }
            }
        }
    }
    let raw: &[u8] = &c.src[start..end];
    let text: String = String::from_utf8_lossy(raw).into_owned();
    let trimmed: String = text.trim().to_owned();
    if trimmed.is_empty() {
        return Err(YaraParseError::MissingCondition {
            rule: rule.to_owned(),
        });
    }
    Ok(trimmed)
}

fn preview_at(src: &[u8], pos: usize) -> String {
    if pos >= src.len() {
        return "<eof>".to_owned();
    }
    let end: usize = (pos + 16).min(src.len());
    String::from_utf8_lossy(&src[pos..end])
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
import "pe"
// leading comment
rule Demo : malware trojan {
    meta:
        author = "x"
        score = 10
    strings:
        $s = "hi"
        $h = { AA BB ?? [2-4] (CC | DD) }
        $r = /re/i
    condition:
        $s and $h /* inline */ or $r
}
"#;

    #[test]
    fn parses_full_rule_all_string_kinds() {
        let ruleset: YaraRuleset = parse_ruleset(SAMPLE).expect("sample must parse");
        assert_eq!(ruleset.imports, vec!["pe".to_owned()]);
        assert_eq!(ruleset.rules.len(), 1);
        let rule: &Rule = &ruleset.rules[0];
        assert_eq!(rule.name, "Demo");
        assert_eq!(rule.tags, vec!["malware".to_owned(), "trojan".to_owned()]);
        assert_eq!(rule.meta.get("author").map(String::as_str), Some("x"));
        assert_eq!(rule.meta.get("score").map(String::as_str), Some("10"));
        assert_eq!(rule.strings.len(), 3);

        let s: &YaraString = &rule.strings[0];
        assert_eq!(s.id, "$s");
        assert_eq!(s.kind, YaraStringKind::Text);
        assert_eq!(s.value, "hi");

        let h: &YaraString = &rule.strings[1];
        assert_eq!(h.id, "$h");
        assert_eq!(h.kind, YaraStringKind::Hex);
        assert!(h.value.contains("AA BB"));

        let r: &YaraString = &rule.strings[2];
        assert_eq!(r.id, "$r");
        assert_eq!(r.kind, YaraStringKind::Regex);
        assert_eq!(r.value, "re");
        assert_eq!(r.modifiers, vec!["i".to_owned()]);

        assert!(rule.condition.contains("$s and $h"));
        assert!(rule.condition.contains("$r"));
        assert!(!rule.condition.contains("inline"));
    }

    #[test]
    fn parses_multi_rule_with_imports_and_modifiers() {
        let src: &str = r#"
import "pe"
rule First { condition: true }
private global rule Second { condition: false }
"#;
        let ruleset: YaraRuleset = parse_ruleset(src).expect("must parse");
        assert_eq!(ruleset.imports, vec!["pe".to_owned()]);
        assert_eq!(ruleset.rules.len(), 2);
        assert_eq!(ruleset.rules[0].name, "First");
        assert_eq!(ruleset.rules[1].name, "Second");
        assert_eq!(
            ruleset.rules[1].modifiers,
            vec!["private".to_owned(), "global".to_owned()]
        );
    }

    #[test]
    fn text_string_modifiers_captured() {
        let src: &str = r#"rule A { strings: $a = "abc" nocase wide condition: $a }"#;
        let rule: Rule = parse_rule(src).expect("must parse");
        assert_eq!(rule.strings[0].value, "abc");
        assert_eq!(
            rule.strings[0].modifiers,
            vec!["nocase".to_owned(), "wide".to_owned()]
        );
    }

    #[test]
    fn strips_line_and_block_comments() {
        let src: &str = r"
// foo
rule A /* bar */ {
    condition: true
}
";
        let rule: Rule = parse_rule(src).expect("must parse");
        assert_eq!(rule.name, "A");
        assert_eq!(rule.condition, "true");
    }

    #[test]
    fn err_missing_rule_name() {
        let src: &str = r"rule { condition: true }";
        let err: YaraParseError = parse_rule(src).expect_err("must reject");
        assert!(matches!(err, YaraParseError::MissingRuleName { .. }));
    }

    #[test]
    fn err_unbalanced_braces() {
        let src: &str = r"rule A { condition: true";
        let err: YaraParseError = parse_rule(src).expect_err("must reject");
        assert!(matches!(err, YaraParseError::UnbalancedBraces { .. }));
    }

    #[test]
    fn err_missing_condition() {
        let src: &str = r#"rule A { strings: $a = "x" }"#;
        let err: YaraParseError = parse_rule(src).expect_err("must reject");
        assert!(matches!(err, YaraParseError::MissingCondition { .. }));
    }

    #[test]
    fn err_malformed_string_assignment() {
        let src: &str = r"rule A { strings: $a = condition: true }";
        let err: YaraParseError = parse_rule(src).expect_err("must reject");
        assert!(matches!(
            err,
            YaraParseError::MalformedStringAssignment { .. }
        ));
    }

    #[test]
    fn err_unterminated_text_string() {
        let src: &str = "rule A { strings: $a = \"oops\n condition: true }";
        let err: YaraParseError = parse_rule(src).expect_err("must reject");
        assert!(matches!(err, YaraParseError::UnterminatedValue { .. }));
    }

    #[test]
    fn err_expected_rule_keyword() {
        let src: &str = r"banana A { condition: true }";
        let err: YaraParseError = parse_rule(src).expect_err("must reject");
        assert!(matches!(err, YaraParseError::ExpectedRuleKeyword { .. }));
    }

    #[test]
    fn err_unknown_section() {
        let src: &str = r#"rule A { bogus: $a = "x" condition: true }"#;
        let err: YaraParseError = parse_rule(src).expect_err("must reject");
        assert!(matches!(err, YaraParseError::UnknownSection { .. }));
    }

    #[test]
    fn report_roundtrips_json() {
        let report: YaraLoaderReport = parse_report(SAMPLE, Some("u.yar")).expect("must parse");
        assert_eq!(report.schema, YARA_SCHEMA);
        assert_eq!(report.rule_count, 1);
        let value: serde_json::Value = serde_json::to_value(&report).expect("must serialize");
        assert_eq!(value["schema"], serde_json::json!(YARA_SCHEMA));
        assert_eq!(value["rule_count"], serde_json::json!(1));
        let back: YaraRuleset =
            serde_json::from_value(value["ruleset"].clone()).expect("must round-trip");
        assert_eq!(back.rules[0].name, "Demo");
        let keys: Vec<&String> = back.rules[0].meta.keys().collect();
        assert_eq!(keys, vec!["author", "score"]);
    }
}
