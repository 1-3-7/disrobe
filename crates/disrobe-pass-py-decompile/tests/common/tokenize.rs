#![allow(dead_code)]

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    Indent,
    Outdent,
    EndLine,
    Word(String),
    Int(i128),
    Float(u64),
    Str { prefix: String, content: String },
    Sym(&'static str),
}

impl Token {
    fn render(&self) -> String {
        match self {
            Self::Indent => "<INDENT>".to_owned(),
            Self::Outdent => "<OUTDENT>".to_owned(),
            Self::EndLine => "<EOL>".to_owned(),
            Self::Word(w) => w.clone(),
            Self::Int(n) => n.to_string(),
            Self::Float(bits) => format_py_float(f64::from_bits(*bits)),
            Self::Str { prefix, content } => format!("{prefix}'{content}'"),
            Self::Sym(s) => (*s).to_owned(),
        }
    }

    const fn is_marker(&self) -> bool {
        matches!(self, Self::Indent | Self::Outdent | Self::EndLine)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenizeError {
    Indentation(usize),
    Unmatched { sym: &'static str, line: usize },
    Unterminated(&'static str),
    Unrecognized { text: String, line: usize },
}

impl std::fmt::Display for TokenizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Indentation(n) => write!(f, "incorrect indentation on line {n}"),
            Self::Unmatched { sym, line } => write!(f, "mismatched token {sym} on line {line}"),
            Self::Unterminated(q) => write!(f, "reached EOF while looking for {q}"),
            Self::Unrecognized { text, line } => {
                write!(f, "unrecognized tokens {text:?} at line {line}")
            }
        }
    }
}

const SYMBOLIC_TOKENS: &[&str] = &[
    "<<=", ">>=", "**=", "//=", "...", ".", "+=", "-=", "*=", "@=", "/=", "%=", "&=", "|=", "^=",
    "<>", "<<", "<=", "<", ">>", ">=", ">", "!=", "==", "=", ",", ";", ":=", ":", "->", "~", "`",
    "+", "-", "**", "*", "@", "//", "/", "%", "&", "|", "^", "(", ")", "{", "}", "[", "]",
];

pub(crate) fn tokenize(source: &str) -> Result<Vec<Token>, TokenizeError> {
    let lines: Vec<&str> = split_keep_newlines(source);
    let mut tokens: Vec<Token> = Vec::new();
    let mut indent_stack: Vec<usize> = vec![0];
    let mut context_stack: Vec<char> = Vec::new();
    let mut idx: usize = 0;
    let mut n_line: usize = 0;
    while idx < lines.len() {
        let mut line: String = lines[idx].to_owned();
        idx += 1;
        n_line += 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if context_stack.is_empty() {
            let indent: usize = line.len() - line.trim_start().len();
            if indent > *indent_stack.last().unwrap_or(&0) {
                indent_stack.push(indent);
                tokens.push(Token::Indent);
            }
            while indent < *indent_stack.last().unwrap_or(&0) {
                indent_stack.pop();
                tokens.push(Token::Outdent);
            }
            if indent != *indent_stack.last().unwrap_or(&0) {
                return Err(TokenizeError::Indentation(n_line));
            }
        }
        loop {
            let trimmed_len: usize = line.len() - line.trim_start().len();
            line.drain(..trimmed_len);
            if line.is_empty() {
                break;
            }
            if line.starts_with('#') {
                break;
            }
            if let Some(sym) = match_symbolic(&line) {
                match sym {
                    "(" | "{" | "[" => context_stack.push(sym.chars().next().unwrap_or('(')),
                    ")" => pop_context(&mut context_stack, '(', sym, n_line)?,
                    "}" => pop_context(&mut context_stack, '{', sym, n_line)?,
                    "]" => pop_context(&mut context_stack, '[', sym, n_line)?,
                    _ => {}
                }
                tokens.push(Token::Sym(sym));
                line.drain(..sym.len());
                continue;
            }
            if let Some((tok, rest)) = match_float(&line) {
                tokens.push(tok);
                line = rest;
                continue;
            }
            if let Some((tok, rest)) = match_int(&line) {
                tokens.push(tok);
                line = rest;
                continue;
            }
            if let Some(start) = StringStart::detect(&line) {
                let (tok, rest_line, consumed_lines): (Token, String, usize) =
                    read_string(&line, &start, &lines, idx)?;
                tokens.push(tok);
                idx += consumed_lines;
                n_line += consumed_lines;
                line = rest_line;
                continue;
            }
            if let Some((word, rest)) = match_word(&line) {
                tokens.push(Token::Word(word));
                line = rest;
                continue;
            }
            return Err(TokenizeError::Unrecognized {
                text: line,
                line: n_line,
            });
        }
        if context_stack.is_empty() {
            tokens.push(Token::EndLine);
        }
    }
    Ok(tokens)
}

#[must_use]
pub(crate) fn render(tokens: &[Token]) -> String {
    let mut out: String = String::new();
    for tok in tokens {
        if tok.is_marker() {
            let _ = writeln!(out, "{}", tok.render());
        } else {
            let _ = write!(out, "{} ", tok.render());
        }
    }
    out
}

fn pop_context(
    stack: &mut Vec<char>,
    expect: char,
    sym: &'static str,
    n_line: usize,
) -> Result<(), TokenizeError> {
    if stack.last() == Some(&expect) {
        stack.pop();
        Ok(())
    } else {
        Err(TokenizeError::Unmatched { sym, line: n_line })
    }
}

fn split_keep_newlines(source: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let bytes: &[u8] = source.as_bytes();
    let mut start: usize = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            out.push(&source[start..=i]);
            start = i + 1;
        }
    }
    if start < source.len() {
        out.push(&source[start..]);
    }
    out
}

fn match_symbolic(line: &str) -> Option<&'static str> {
    SYMBOLIC_TOKENS
        .iter()
        .copied()
        .find(|&tok| line.starts_with(tok))
}

fn match_word(line: &str) -> Option<(String, String)> {
    let mut chars = line.char_indices();
    let (_, first): (usize, char) = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    let mut end: usize = first.len_utf8();
    for (i, c) in chars {
        if c.is_ascii_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    Some((line[..end].to_owned(), line[end..].to_owned()))
}

fn match_int(line: &str) -> Option<(Token, String)> {
    let (matched, rest): (&str, &str) = scan_int(line)?;
    let cleaned: String = matched.replace('_', "");
    let value: i128 = parse_int_with_radix(&cleaned)?;
    Some((Token::Int(value), rest.to_owned()))
}

fn scan_int(line: &str) -> Option<(&str, &str)> {
    let bytes: &[u8] = line.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }
    scan_decimal(line)
}

fn scan_decimal(line: &str) -> Option<(&str, &str)> {
    let bytes: &[u8] = line.as_bytes();
    let mut end: usize = 0;
    while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'_') {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    Some((&line[..end], &line[end..]))
}

fn parse_int_with_radix(cleaned: &str) -> Option<i128> {
    if cleaned.len() > 1 && cleaned.starts_with('0') {
        i128::from_str_radix(cleaned, 8)
            .ok()
            .or_else(|| cleaned.parse::<i128>().ok())
    } else {
        cleaned.parse::<i128>().ok()
    }
}

fn match_float(line: &str) -> Option<(Token, String)> {
    let (matched, rest): (&str, &str) = scan_float(line)?;
    let cleaned: String = matched.replace('_', "");
    let value: f64 = cleaned.parse::<f64>().ok()?;
    Some((Token::Float(value.to_bits()), rest.to_owned()))
}

fn scan_float(line: &str) -> Option<(&str, &str)> {
    let bytes: &[u8] = line.as_bytes();
    let mut i: usize = 0;
    let mut saw_digit: bool = false;
    let mut saw_dot: bool = false;
    while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
        if bytes[i].is_ascii_digit() {
            saw_digit = true;
        }
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        saw_dot = true;
        i += 1;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
            if bytes[i].is_ascii_digit() {
                saw_digit = true;
            }
            i += 1;
        }
    }
    if !saw_dot || !saw_digit {
        return None;
    }
    if i < bytes.len() && (bytes[i] | 0x20) == b'e' {
        let mut j: usize = i + 1;
        if j < bytes.len() && (bytes[j] == b'+' || bytes[j] == b'-') {
            j += 1;
        }
        let exp_start: usize = j;
        while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'_') {
            j += 1;
        }
        if j > exp_start {
            i = j;
        }
    }
    Some((&line[..i], &line[i..]))
}

#[derive(Debug, Clone)]
struct StringStart {
    prefix: String,
    quote: &'static str,
}

impl StringStart {
    fn detect(line: &str) -> Option<Self> {
        let bytes: &[u8] = line.as_bytes();
        let mut prefix_len: usize = 0;
        while prefix_len < bytes.len() && prefix_len < 2 {
            let c: u8 = bytes[prefix_len] | 0x20;
            if matches!(c, b'r' | b'f' | b'b' | b'u') {
                prefix_len += 1;
            } else {
                break;
            }
        }
        let rest: &str = &line[prefix_len..];
        let quote: &'static str = if rest.starts_with("'''") {
            "'''"
        } else if rest.starts_with("\"\"\"") {
            "\"\"\""
        } else if rest.starts_with('\'') {
            "'"
        } else if rest.starts_with('"') {
            "\""
        } else {
            return None;
        };
        Some(Self {
            prefix: line[..prefix_len].to_owned(),
            quote,
        })
    }
}

fn read_string(
    first_line: &str,
    start: &StringStart,
    lines: &[&str],
    next_idx: usize,
) -> Result<(Token, String, usize), TokenizeError> {
    let quote: &str = start.quote;
    let body_start: usize = start.prefix.len() + quote.len();
    let mut content: String = String::new();
    let mut current: String = first_line.to_owned();
    let mut search_from: usize = body_start;
    let mut consumed: usize = 0;
    loop {
        if let Some(rel) = current[search_from..].find(quote) {
            let end: usize = search_from + rel;
            let escaped: bool = end > 0 && current.as_bytes()[end - 1] == b'\\';
            if escaped {
                content.push_str(&current[search_from..=end]);
                search_from = end + 1;
                continue;
            }
            content.push_str(&current[search_from..end]);
            let rest: String = current[end + quote.len()..].to_owned();
            let token: Token = Token::Str {
                prefix: normalize_prefix(&start.prefix),
                content: normalize_content(&content),
            };
            return Ok((token, rest, consumed));
        }
        content.push_str(&current[search_from..]);
        let line_idx: usize = next_idx + consumed;
        let Some(next): Option<&&str> = lines.get(line_idx) else {
            return Err(TokenizeError::Unterminated(start.quote));
        };
        (*next).clone_into(&mut current);
        consumed += 1;
        search_from = 0;
    }
}

fn normalize_prefix(prefix: &str) -> String {
    let mut chars: Vec<char> = prefix.to_ascii_lowercase().chars().collect();
    chars.sort_unstable();
    chars.into_iter().collect()
}

fn normalize_content(content: &str) -> String {
    content
        .replace("\\'", "'")
        .replace('\'', "\\'")
        .replace("\\\"", "\"")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn format_py_float(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e16 {
        format!("{value:.1}")
    } else {
        let mut s: String = format!("{value}");
        if !s.contains('.') && !s.contains('e') && !s.contains('E') && value.is_finite() {
            s.push_str(".0");
        }
        s
    }
}
