use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

const MAX_TOKEN_COUNT: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokKind {
    InlineHtml,
    OpenTag,
    OpenTagWithEcho,
    ShortOpenTag,
    CloseTag,
    Whitespace,
    LineComment,
    BlockComment,
    DocComment,
    Variable,
    Ident,
    LongNumber,
    DoubleNumber,
    StringSingle,
    StringDouble,
    Heredoc,
    Nowdoc,
    Punct,
    NamespaceSep,
    DoubleArrow,
    ObjectOp,
    NullsafeOp,
    ScopeRes,
    Spread,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token<'a> {
    pub kind: TokKind,
    pub lexeme: &'a [u8],
    pub start: usize,
    pub end: usize,
    pub line: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Html,
    Php,
}

#[derive(Debug)]
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    mode: Mode,
}

impl<'a> Lexer<'a> {
    #[must_use]
    pub fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            line: 1,
            mode: Mode::Html,
        }
    }

    pub fn tokens(mut self) -> Result<Vec<Token<'a>>> {
        let mut out: Vec<Token<'a>> = Vec::new();
        while let Some(tok) = self.next_token()? {
            if matches!(tok.kind, TokKind::Eof) {
                break;
            }
            if tok.end <= tok.start {
                return Err(Error::TokenNoProgress { offset: tok.start });
            }
            if self.pos != tok.end {
                return Err(Error::TokenNoProgress { offset: tok.start });
            }
            if out.len() >= MAX_TOKEN_COUNT {
                return Err(Error::TokenCountExceeded {
                    cap: MAX_TOKEN_COUNT,
                });
            }
            out.push(tok);
        }
        Ok(out)
    }

    fn next_token(&mut self) -> Result<Option<Token<'a>>> {
        if self.pos >= self.src.len() {
            return Ok(None);
        }
        match self.mode {
            Mode::Html => self.scan_html(),
            Mode::Php => self.scan_php(),
        }
    }

    fn scan_html(&mut self) -> Result<Option<Token<'a>>> {
        let start: usize = self.pos;
        let start_line: u32 = self.line;
        while self.pos < self.src.len() {
            let b: u8 = self.src[self.pos];
            if b == b'<' && self.peek_open_tag().is_some() {
                if self.pos > start {
                    let lexeme: &'a [u8] = &self.src[start..self.pos];
                    return Ok(Some(Token {
                        kind: TokKind::InlineHtml,
                        lexeme,
                        start,
                        end: self.pos,
                        line: start_line,
                    }));
                }
                return self.consume_open_tag().map(Some);
            }
            if b == b'\n' {
                self.line = self.line.saturating_add(1);
            }
            self.pos += 1;
        }
        if self.pos > start {
            let lexeme: &'a [u8] = &self.src[start..self.pos];
            return Ok(Some(Token {
                kind: TokKind::InlineHtml,
                lexeme,
                start,
                end: self.pos,
                line: start_line,
            }));
        }
        Ok(None)
    }

    fn peek_open_tag(&self) -> Option<(usize, TokKind)> {
        let rest: &[u8] = &self.src[self.pos..];
        if rest.starts_with(b"<?php") {
            return Some((5, TokKind::OpenTag));
        }
        if rest.starts_with(b"<?=") {
            return Some((3, TokKind::OpenTagWithEcho));
        }
        if rest.starts_with(b"<?") {
            return Some((2, TokKind::ShortOpenTag));
        }
        None
    }

    fn consume_open_tag(&mut self) -> Result<Token<'a>> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        let Some((len, kind)): Option<(usize, TokKind)> = self.peek_open_tag() else {
            return Err(Error::TokenTruncated {
                offset: start,
                reason: "expected open tag",
            });
        };
        self.pos += len;
        let lexeme: &'a [u8] = &self.src[start..self.pos];
        self.mode = Mode::Php;
        Ok(Token {
            kind,
            lexeme,
            start,
            end: self.pos,
            line,
        })
    }

    fn scan_php(&mut self) -> Result<Option<Token<'a>>> {
        if self.pos >= self.src.len() {
            return Ok(None);
        }
        let b: u8 = self.src[self.pos];

        if b.is_ascii_whitespace() {
            return Ok(Some(self.scan_whitespace()));
        }
        if b == b'?' && self.src.get(self.pos + 1).copied() == Some(b'>') {
            return Ok(Some(self.scan_close_tag()));
        }
        if b == b'/' {
            if self.src.get(self.pos + 1).copied() == Some(b'/') {
                return Ok(Some(self.scan_line_comment()));
            }
            if self.src.get(self.pos + 1).copied() == Some(b'*') {
                return self.scan_block_comment().map(Some);
            }
        }
        if b == b'#' {
            return Ok(Some(self.scan_line_comment()));
        }
        if b == b'$' {
            return self.scan_variable().map(Some);
        }
        if b == b'\'' {
            return self.scan_single_string().map(Some);
        }
        if b == b'"' {
            return self.scan_double_string().map(Some);
        }
        if b == b'<'
            && self.src.get(self.pos + 1).copied() == Some(b'<')
            && self.src.get(self.pos + 2).copied() == Some(b'<')
        {
            return self.scan_heredoc_or_nowdoc().map(Some);
        }
        if b.is_ascii_digit() {
            return Ok(Some(self.scan_number()));
        }
        if b == b'.' && self.src.get(self.pos + 1).is_some_and(u8::is_ascii_digit) {
            return Ok(Some(self.scan_number()));
        }
        if is_ident_start(b) {
            return Ok(Some(self.scan_ident()));
        }
        Ok(Some(self.scan_punct()))
    }

    fn scan_whitespace(&mut self) -> Token<'a> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            if self.src[self.pos] == b'\n' {
                self.line = self.line.saturating_add(1);
            }
            self.pos += 1;
        }
        let lexeme: &'a [u8] = &self.src[start..self.pos];
        Token {
            kind: TokKind::Whitespace,
            lexeme,
            start,
            end: self.pos,
            line,
        }
    }

    fn scan_close_tag(&mut self) -> Token<'a> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        self.pos += 2;
        if self.src.get(self.pos).copied() == Some(b'\n') {
            self.line = self.line.saturating_add(1);
            self.pos += 1;
        }
        let lexeme: &'a [u8] = &self.src[start..self.pos];
        self.mode = Mode::Html;
        Token {
            kind: TokKind::CloseTag,
            lexeme,
            start,
            end: self.pos,
            line,
        }
    }

    fn scan_line_comment(&mut self) -> Token<'a> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        while self.pos < self.src.len() {
            let b: u8 = self.src[self.pos];
            if b == b'\n' {
                break;
            }
            if b == b'?' && self.src.get(self.pos + 1).copied() == Some(b'>') {
                break;
            }
            self.pos += 1;
        }
        let lexeme: &'a [u8] = &self.src[start..self.pos];
        Token {
            kind: TokKind::LineComment,
            lexeme,
            start,
            end: self.pos,
            line,
        }
    }

    fn scan_block_comment(&mut self) -> Result<Token<'a>> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        let is_doc: bool = self.src.get(self.pos + 2).copied() == Some(b'*')
            && self.src.get(self.pos + 3).copied() != Some(b'/');
        self.pos += 2;
        while self.pos + 1 < self.src.len() {
            if self.src[self.pos] == b'\n' {
                self.line = self.line.saturating_add(1);
            }
            if self.src[self.pos] == b'*' && self.src[self.pos + 1] == b'/' {
                self.pos += 2;
                let lexeme: &'a [u8] = &self.src[start..self.pos];
                let kind: TokKind = if is_doc {
                    TokKind::DocComment
                } else {
                    TokKind::BlockComment
                };
                return Ok(Token {
                    kind,
                    lexeme,
                    start,
                    end: self.pos,
                    line,
                });
            }
            self.pos += 1;
        }
        Err(Error::UnterminatedToken {
            kind: "block comment",
            offset: start,
        })
    }

    fn scan_variable(&mut self) -> Result<Token<'a>> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        self.pos += 1;
        while self.pos < self.src.len() && is_ident_cont(self.src[self.pos]) {
            self.pos += 1;
        }
        if self.pos == start + 1 {
            return Err(Error::TokenTruncated {
                offset: start,
                reason: "lone $",
            });
        }
        let lexeme: &'a [u8] = &self.src[start..self.pos];
        Ok(Token {
            kind: TokKind::Variable,
            lexeme,
            start,
            end: self.pos,
            line,
        })
    }

    fn scan_single_string(&mut self) -> Result<Token<'a>> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        self.pos += 1;
        while self.pos < self.src.len() {
            let b: u8 = self.src[self.pos];
            if b == b'\\' && self.pos + 1 < self.src.len() {
                self.pos += 2;
                continue;
            }
            if b == b'\'' {
                self.pos += 1;
                let lexeme: &'a [u8] = &self.src[start..self.pos];
                return Ok(Token {
                    kind: TokKind::StringSingle,
                    lexeme,
                    start,
                    end: self.pos,
                    line,
                });
            }
            if b == b'\n' {
                self.line = self.line.saturating_add(1);
            }
            self.pos += 1;
        }
        Err(Error::UnterminatedToken {
            kind: "single-quoted string",
            offset: start,
        })
    }

    fn scan_double_string(&mut self) -> Result<Token<'a>> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        self.pos += 1;
        while self.pos < self.src.len() {
            let b: u8 = self.src[self.pos];
            if b == b'\\' && self.pos + 1 < self.src.len() {
                self.pos += 2;
                continue;
            }
            if b == b'"' {
                self.pos += 1;
                let lexeme: &'a [u8] = &self.src[start..self.pos];
                return Ok(Token {
                    kind: TokKind::StringDouble,
                    lexeme,
                    start,
                    end: self.pos,
                    line,
                });
            }
            if b == b'\n' {
                self.line = self.line.saturating_add(1);
            }
            self.pos += 1;
        }
        Err(Error::UnterminatedToken {
            kind: "double-quoted string",
            offset: start,
        })
    }

    fn scan_heredoc_or_nowdoc(&mut self) -> Result<Token<'a>> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        self.pos += 3;
        let nowdoc: bool = self.src.get(self.pos).copied() == Some(b'\'');
        if nowdoc || self.src.get(self.pos).copied() == Some(b'"') {
            self.pos += 1;
        }
        let label_start: usize = self.pos;
        while self.pos < self.src.len() && is_ident_cont(self.src[self.pos]) {
            self.pos += 1;
        }
        let label_end: usize = self.pos;
        if label_end == label_start {
            return Err(Error::TokenTruncated {
                offset: start,
                reason: "heredoc/nowdoc missing label",
            });
        }
        let expected_close: u8 = if nowdoc { b'\'' } else { b'"' };
        if self.src.get(self.pos).copied() == Some(expected_close) {
            self.pos += 1;
        }
        if self.src.get(self.pos).copied() == Some(b'\n') {
            self.line = self.line.saturating_add(1);
            self.pos += 1;
        }
        let label: &[u8] = &self.src[label_start..label_end];
        while self.pos < self.src.len() {
            if self.src[self.pos] == b'\n' {
                self.line = self.line.saturating_add(1);
                let line_start: usize = self.pos + 1;
                let mut probe: usize = line_start;
                while probe < self.src.len()
                    && (self.src[probe] == b' ' || self.src[probe] == b'\t')
                {
                    probe += 1;
                }
                let label_end: usize =
                    probe
                        .checked_add(label.len())
                        .ok_or(Error::TokenTruncated {
                            offset: probe,
                            reason: "heredoc label range overflow",
                        })?;
                if self.src.get(probe..label_end) == Some(label) {
                    self.pos = label_end;
                    let kind: TokKind = if nowdoc {
                        TokKind::Nowdoc
                    } else {
                        TokKind::Heredoc
                    };
                    let lexeme: &'a [u8] = &self.src[start..self.pos];
                    return Ok(Token {
                        kind,
                        lexeme,
                        start,
                        end: self.pos,
                        line,
                    });
                }
            }
            self.pos += 1;
        }
        Err(Error::UnterminatedToken {
            kind: "heredoc/nowdoc",
            offset: start,
        })
    }

    fn scan_number(&mut self) -> Token<'a> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        let mut is_double: bool = false;
        if self.src[self.pos] == b'0'
            && matches!(self.src.get(self.pos + 1).copied(), Some(b'x' | b'X'))
        {
            self.pos += 2;
            while self.pos < self.src.len()
                && (self.src[self.pos].is_ascii_hexdigit() || self.src[self.pos] == b'_')
            {
                self.pos += 1;
            }
        } else if self.src[self.pos] == b'0'
            && matches!(self.src.get(self.pos + 1).copied(), Some(b'b' | b'B'))
        {
            self.pos += 2;
            while self.pos < self.src.len() && matches!(self.src[self.pos], b'0' | b'1' | b'_') {
                self.pos += 1;
            }
        } else {
            while self.pos < self.src.len()
                && (self.src[self.pos].is_ascii_digit() || self.src[self.pos] == b'_')
            {
                self.pos += 1;
            }
            if self.src.get(self.pos).copied() == Some(b'.')
                && self.src.get(self.pos + 1).is_some_and(u8::is_ascii_digit)
            {
                is_double = true;
                self.pos += 1;
                while self.pos < self.src.len()
                    && (self.src[self.pos].is_ascii_digit() || self.src[self.pos] == b'_')
                {
                    self.pos += 1;
                }
            }
            if matches!(self.src.get(self.pos).copied(), Some(b'e' | b'E')) {
                is_double = true;
                self.pos += 1;
                if matches!(self.src.get(self.pos).copied(), Some(b'+' | b'-')) {
                    self.pos += 1;
                }
                while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
            }
        }
        let lexeme: &'a [u8] = &self.src[start..self.pos];
        let kind: TokKind = if is_double {
            TokKind::DoubleNumber
        } else {
            TokKind::LongNumber
        };
        Token {
            kind,
            lexeme,
            start,
            end: self.pos,
            line,
        }
    }

    fn scan_ident(&mut self) -> Token<'a> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        while self.pos < self.src.len() && is_ident_cont(self.src[self.pos]) {
            self.pos += 1;
        }
        let lexeme: &'a [u8] = &self.src[start..self.pos];
        Token {
            kind: TokKind::Ident,
            lexeme,
            start,
            end: self.pos,
            line,
        }
    }

    fn scan_punct(&mut self) -> Token<'a> {
        let start: usize = self.pos;
        let line: u32 = self.line;
        let b: u8 = self.src[self.pos];
        let second: Option<u8> = self.src.get(self.pos + 1).copied();
        let third: Option<u8> = self.src.get(self.pos + 2).copied();
        let (len, kind): (usize, TokKind) = match (b, second, third) {
            (b'.', Some(b'.'), Some(b'.')) => (3, TokKind::Spread),
            (b'=', Some(b'>'), _) => (2, TokKind::DoubleArrow),
            (b'-', Some(b'>'), _) => (2, TokKind::ObjectOp),
            (b'?', Some(b'-'), Some(b'>')) => (3, TokKind::NullsafeOp),
            (b':', Some(b':'), _) => (2, TokKind::ScopeRes),
            (b'\\', _, _) => (1, TokKind::NamespaceSep),
            _ => (1, TokKind::Punct),
        };
        self.pos += len;
        let lexeme: &'a [u8] = &self.src[start..self.pos];
        Token {
            kind,
            lexeme,
            start,
            end: self.pos,
            line,
        }
    }
}

const fn is_ident_start(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'_' | 0x80..=0xff)
}

const fn is_ident_cont(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | 0x80..=0xff)
}

pub fn tokenize(src: &[u8]) -> Result<Vec<Token<'_>>> {
    Lexer::new(src).tokens()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn punctuation_flood_is_rejected_before_token_growth() {
        let mut source: Vec<u8> = b"<?php ".to_vec();
        source.extend(std::iter::repeat_n(b';', 1_000_001));

        assert!(tokenize(&source).is_err());
    }
}
