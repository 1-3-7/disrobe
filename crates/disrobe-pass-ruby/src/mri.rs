use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Result, RubyError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TokenKind {
    Keyword,
    Identifier,
    Constant,
    InstanceVar,
    ClassVar,
    GlobalVar,
    StringLit,
    SymbolLit,
    IntLit,
    FloatLit,
    Operator,
    Punct,
    Comment,
    Newline,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub value: String,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefinitionRecord {
    pub kind: String,
    pub name: String,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MriAst {
    pub source_hash: [u8; 32],
    pub line_count: u32,
    pub token_count: u32,
    pub tokens: Vec<Token>,
    pub definitions: Vec<DefinitionRecord>,
    pub requires: Vec<String>,
    pub keyword_histogram: BTreeMap<String, u32>,
}

const KEYWORDS: &[&str] = &[
    "BEGIN",
    "END",
    "alias",
    "and",
    "begin",
    "break",
    "case",
    "class",
    "def",
    "defined?",
    "do",
    "else",
    "elsif",
    "end",
    "ensure",
    "false",
    "for",
    "if",
    "in",
    "module",
    "next",
    "nil",
    "not",
    "or",
    "redo",
    "rescue",
    "retry",
    "return",
    "self",
    "super",
    "then",
    "true",
    "undef",
    "unless",
    "until",
    "when",
    "while",
    "yield",
    "__FILE__",
    "__LINE__",
    "__ENCODING__",
];

#[inline]
const fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

#[inline]
const fn is_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[inline]
fn is_keyword(s: &str) -> bool {
    KEYWORDS.binary_search(&s).is_ok()
}

#[inline]
const fn is_op_char(b: u8) -> bool {
    matches!(
        b,
        b'+' | b'-' | b'*' | b'/' | b'%' | b'=' | b'<' | b'>' | b'!' | b'&' | b'|' | b'^' | b'~'
    )
}

#[derive(Debug)]
enum WsResult {
    Newline(Token),
    Skipped,
    NotWhitespace,
}

#[derive(Debug)]
struct Lexer<'a> {
    bytes: &'a [u8],
    i: usize,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            i: 0,
            line: 1,
            col: 1,
        }
    }

    fn run(mut self, out: &mut Vec<Token>) -> u32 {
        while self.i < self.bytes.len() {
            let b: u8 = self.bytes[self.i];
            match self.consume_whitespace_or_newline(b) {
                WsResult::Newline(tok) => {
                    out.push(tok);
                    continue;
                }
                WsResult::Skipped => continue,
                WsResult::NotWhitespace => {}
            }
            if b == b'#' {
                out.push(self.consume_comment());
                continue;
            }
            if b == b'"' || b == b'\'' {
                out.push(self.consume_string(b));
                continue;
            }
            if b == b':' && self.peek_is_ident_start() {
                out.push(self.consume_symbol());
                continue;
            }
            if b == b'@' || b == b'$' {
                out.push(self.consume_var(b));
                continue;
            }
            if b.is_ascii_digit() {
                out.push(self.consume_number());
                continue;
            }
            if is_ident_start(b) {
                out.push(self.consume_ident());
                continue;
            }
            out.push(self.consume_punct(b));
        }
        self.line
    }

    fn consume_whitespace_or_newline(&mut self, b: u8) -> WsResult {
        if b == b'\n' {
            let tok: Token = Token {
                kind: TokenKind::Newline,
                value: "\\n".to_owned(),
                line: self.line,
                col: self.col,
            };
            self.line += 1;
            self.col = 1;
            self.i += 1;
            return WsResult::Newline(tok);
        }
        if b == b' ' || b == b'\t' || b == b'\r' {
            self.i += 1;
            self.col += 1;
            return WsResult::Skipped;
        }
        WsResult::NotWhitespace
    }

    fn consume_comment(&mut self) -> Token {
        let start: usize = self.i;
        let (line, col): (u32, u32) = (self.line, self.col);
        while self.i < self.bytes.len() && self.bytes[self.i] != b'\n' {
            self.i += 1;
        }
        self.col = 1;
        Token {
            kind: TokenKind::Comment,
            value: String::from_utf8_lossy(&self.bytes[start..self.i]).into_owned(),
            line,
            col,
        }
    }

    fn consume_string(&mut self, quote: u8) -> Token {
        let start: usize = self.i;
        let (line, col): (u32, u32) = (self.line, self.col);
        self.i += 1;
        self.col += 1;
        while self.i < self.bytes.len() && self.bytes[self.i] != quote {
            if self.bytes[self.i] == b'\\' && self.i + 1 < self.bytes.len() {
                self.i += 2;
                self.col += 2;
                continue;
            }
            if self.bytes[self.i] == b'\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
            self.i += 1;
        }
        if self.i < self.bytes.len() {
            self.i += 1;
            self.col += 1;
        }
        Token {
            kind: TokenKind::StringLit,
            value: String::from_utf8_lossy(&self.bytes[start..self.i]).into_owned(),
            line,
            col,
        }
    }

    fn peek_is_ident_start(&self) -> bool {
        self.i + 1 < self.bytes.len() && is_ident_start(self.bytes[self.i + 1])
    }

    fn consume_symbol(&mut self) -> Token {
        let start: usize = self.i;
        let (line, col): (u32, u32) = (self.line, self.col);
        self.i += 1;
        self.col += 1;
        while self.i < self.bytes.len() && is_ident_cont(self.bytes[self.i]) {
            self.i += 1;
            self.col += 1;
        }
        Token {
            kind: TokenKind::SymbolLit,
            value: String::from_utf8_lossy(&self.bytes[start..self.i]).into_owned(),
            line,
            col,
        }
    }

    fn consume_var(&mut self, leading: u8) -> Token {
        let start: usize = self.i;
        let (line, col): (u32, u32) = (self.line, self.col);
        self.i += 1;
        self.col += 1;
        if leading == b'@' && self.i < self.bytes.len() && self.bytes[self.i] == b'@' {
            self.i += 1;
            self.col += 1;
        }
        while self.i < self.bytes.len() && is_ident_cont(self.bytes[self.i]) {
            self.i += 1;
            self.col += 1;
        }
        let value: String = String::from_utf8_lossy(&self.bytes[start..self.i]).into_owned();
        let kind: TokenKind = if leading == b'$' {
            TokenKind::GlobalVar
        } else if value.starts_with("@@") {
            TokenKind::ClassVar
        } else {
            TokenKind::InstanceVar
        };
        Token {
            kind,
            value,
            line,
            col,
        }
    }

    fn consume_number(&mut self) -> Token {
        let start: usize = self.i;
        let (line, col): (u32, u32) = (self.line, self.col);
        let mut saw_dot: bool = false;
        while self.i < self.bytes.len() {
            let cb: u8 = self.bytes[self.i];
            let is_digit_run: bool = cb.is_ascii_digit() || cb == b'_';
            let is_dec_dot: bool = !saw_dot
                && cb == b'.'
                && self.i + 1 < self.bytes.len()
                && self.bytes[self.i + 1].is_ascii_digit();
            if !is_digit_run && !is_dec_dot {
                break;
            }
            if cb == b'.' {
                saw_dot = true;
            }
            self.i += 1;
            self.col += 1;
        }
        Token {
            kind: if saw_dot {
                TokenKind::FloatLit
            } else {
                TokenKind::IntLit
            },
            value: String::from_utf8_lossy(&self.bytes[start..self.i]).into_owned(),
            line,
            col,
        }
    }

    fn consume_ident(&mut self) -> Token {
        let start: usize = self.i;
        let (line, col): (u32, u32) = (self.line, self.col);
        while self.i < self.bytes.len() && is_ident_cont(self.bytes[self.i]) {
            self.i += 1;
            self.col += 1;
        }
        if self.i < self.bytes.len() && (self.bytes[self.i] == b'?' || self.bytes[self.i] == b'!') {
            self.i += 1;
            self.col += 1;
        }
        let value: String = String::from_utf8_lossy(&self.bytes[start..self.i]).into_owned();
        let first: u8 = value.as_bytes()[0];
        let kind: TokenKind = if is_keyword(&value) {
            TokenKind::Keyword
        } else if first.is_ascii_uppercase() {
            TokenKind::Constant
        } else {
            TokenKind::Identifier
        };
        Token {
            kind,
            value,
            line,
            col,
        }
    }

    fn consume_punct(&mut self, b: u8) -> Token {
        let start: usize = self.i;
        let (line, col): (u32, u32) = (self.line, self.col);
        let kind: TokenKind = if is_op_char(b) {
            TokenKind::Operator
        } else {
            TokenKind::Punct
        };
        self.i += 1;
        self.col += 1;
        Token {
            kind,
            value: String::from_utf8_lossy(&self.bytes[start..self.i]).into_owned(),
            line,
            col,
        }
    }
}

fn collect_metadata(
    tokens: &[Token],
) -> (Vec<DefinitionRecord>, Vec<String>, BTreeMap<String, u32>) {
    let mut definitions: Vec<DefinitionRecord> = Vec::new();
    let mut requires: Vec<String> = Vec::new();
    let mut keyword_histogram: BTreeMap<String, u32> = BTreeMap::new();
    let mut idx: usize = 0usize;
    while idx < tokens.len() {
        let tok: &Token = &tokens[idx];
        if tok.kind == TokenKind::Keyword {
            *keyword_histogram.entry(tok.value.clone()).or_insert(0) += 1;
            if matches!(tok.value.as_str(), "def" | "class" | "module") {
                let mut j: usize = idx + 1;
                while j < tokens.len() && tokens[j].kind == TokenKind::Newline {
                    j += 1;
                }
                if let Some(name_tok) = tokens.get(j) {
                    definitions.push(DefinitionRecord {
                        kind: tok.value.clone(),
                        name: name_tok.value.clone(),
                        line: tok.line,
                    });
                }
            }
        }
        if tok.kind == TokenKind::Identifier && tok.value == "require" {
            let mut j: usize = idx + 1;
            while j < tokens.len() && tokens[j].kind == TokenKind::Punct && tokens[j].value == "(" {
                j += 1;
            }
            if let Some(arg) = tokens.get(j)
                && arg.kind == TokenKind::StringLit
            {
                let trimmed: String = arg
                    .value
                    .trim_matches(|c: char| c == '"' || c == '\'')
                    .to_owned();
                requires.push(trimmed);
            }
        }
        idx += 1;
    }
    (definitions, requires, keyword_histogram)
}

pub(crate) fn parse_mri(bytes: &[u8], _source_path: &str) -> Result<MriAst> {
    let text: &str = std::str::from_utf8(bytes).map_err(|e| RubyError::MriBadUtf8 {
        at: e.valid_up_to(),
    })?;
    let source_hash: [u8; 32] = blake3::hash(bytes).into();
    let mut tokens: Vec<Token> = Vec::with_capacity(text.len() / 8);
    let line_count: u32 = Lexer::new(text.as_bytes()).run(&mut tokens);
    let (definitions, requires, keyword_histogram): (
        Vec<DefinitionRecord>,
        Vec<String>,
        BTreeMap<String, u32>,
    ) = collect_metadata(&tokens);
    let token_count: u32 = u32::try_from(tokens.len()).unwrap_or(u32::MAX);
    Ok(MriAst {
        source_hash,
        line_count,
        token_count,
        tokens,
        definitions,
        requires,
        keyword_histogram,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_def_class_module() {
        let src: &str = "module Foo\n  class Bar\n    def baz; end\n  end\nend\n";
        let ast: MriAst = parse_mri(src.as_bytes(), "x.rb").expect("parse");
        let kinds: Vec<&str> = ast.definitions.iter().map(|d| d.kind.as_str()).collect();
        assert_eq!(kinds, vec!["module", "class", "def"]);
        let names: Vec<&str> = ast.definitions.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["Foo", "Bar", "baz"]);
    }

    #[test]
    fn collects_requires() {
        let src: &str = "require 'json'\nrequire(\"yaml\")\n";
        let ast: MriAst = parse_mri(src.as_bytes(), "x.rb").expect("parse");
        assert_eq!(ast.requires, vec!["json".to_owned(), "yaml".to_owned()]);
    }

    #[test]
    fn tokenizes_basic_literals() {
        let src: &str = "x = 1 + 2.5\ny = :sym\n@iv = $g\n";
        let ast: MriAst = parse_mri(src.as_bytes(), "x.rb").expect("parse");
        let mut saw_int: bool = false;
        let mut saw_float: bool = false;
        let mut saw_symbol: bool = false;
        let mut saw_instance: bool = false;
        let mut saw_global: bool = false;
        for t in &ast.tokens {
            match t.kind {
                TokenKind::IntLit => saw_int = true,
                TokenKind::FloatLit => saw_float = true,
                TokenKind::SymbolLit => saw_symbol = true,
                TokenKind::InstanceVar => saw_instance = true,
                TokenKind::GlobalVar => saw_global = true,
                _ => {}
            }
        }
        assert!(saw_int && saw_float && saw_symbol && saw_instance && saw_global);
    }

    #[test]
    fn rejects_invalid_utf8() {
        let bytes: Vec<u8> = vec![0xFFu8, 0xFEu8, b'x'];
        let err: RubyError = parse_mri(&bytes, "x.rb").expect_err("must reject");
        assert!(matches!(err, RubyError::MriBadUtf8 { .. }));
    }
}
