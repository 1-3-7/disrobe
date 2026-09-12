use serde::Serialize;

const MAX_TOKEN_COUNT: usize = 65_536usize;
const MAX_TOKEN_TEXT_BYTES: usize = 65_536usize;
const MAX_TOKEN_SOURCE_BYTES: usize = MAX_TOKEN_TEXT_BYTES / 3usize;
const MAX_TOTAL_TOKEN_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_LEXER_INPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TokenKind {
    Identifier,
    Variable,
    Number,
    StringDq,
    StringSq,
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Semicolon,
    Pipe,
    Ampersand,
    Dot,
    Equals,
    PlusEq,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Backtick,
    Newline,
    Whitespace,
    Comment,
    Truncated,
    Eof,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Token {
    pub kind: TokenKind,
    pub text: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    scan_end: usize,
}

impl<'a> Lexer<'a> {
    #[inline]
    #[must_use]
    pub const fn new(src: &'a [u8]) -> Self {
        let scan_end: usize = if src.len() > MAX_LEXER_INPUT_BYTES {
            MAX_LEXER_INPUT_BYTES
        } else {
            src.len()
        };
        Self {
            src,
            pos: 0,
            scan_end,
        }
    }

    #[must_use]
    pub fn tokenize(mut self) -> Vec<Token> {
        let source_len: usize = self.src.len();
        let initial_capacity: usize = (self.scan_end / 4usize)
            .saturating_add(8usize)
            .min(MAX_TOKEN_COUNT.saturating_add(1usize));
        let mut out: Vec<Token> = Vec::with_capacity(initial_capacity);
        let mut text_budget: usize = MAX_TOTAL_TOKEN_TEXT_BYTES;
        let mut truncation: Option<(usize, usize)> =
            (self.scan_end < source_len).then_some((self.scan_end, source_len));
        while out.len() < MAX_TOKEN_COUNT {
            let Some(mut tok): Option<Token> = self.next_token() else {
                break;
            };
            if tok.kind == TokenKind::Eof {
                break;
            }
            let source_limit_exceeded: bool =
                tok.end.saturating_sub(tok.start) > MAX_TOKEN_SOURCE_BYTES;
            let text_budget_exceeded: bool = truncate_token_text(&mut tok.text, &mut text_budget);
            let token_truncated: bool = source_limit_exceeded || text_budget_exceeded;
            if token_truncated && truncation.is_none() {
                truncation = Some((tok.start, source_len));
            }
            out.push(tok);
            if token_truncated {
                break;
            }
        }
        if self.pos < self.scan_end && truncation.is_none() {
            truncation = Some((self.pos, source_len));
        }
        if let Some((start, end)) = truncation {
            out.push(Token {
                kind: TokenKind::Truncated,
                text: String::new(),
                start,
                end,
            });
        }
        out.push(Token {
            kind: TokenKind::Eof,
            text: String::new(),
            start: source_len,
            end: source_len,
        });
        out
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.pos >= self.scan_end {
            return Some(Token {
                kind: TokenKind::Eof,
                text: String::new(),
                start: self.pos,
                end: self.pos,
            });
        }
        let start: usize = self.pos;
        let b: u8 = self.src[self.pos];
        let tok: Token = match b {
            b' ' | b'\t' | b'\r' => self.consume_whitespace(start),
            b'\n' => self.consume_single(start, TokenKind::Newline),
            b'#' => self.consume_comment(start),
            b'$' => self.consume_variable(start),
            b'"' => self.consume_string_dq(start),
            b'\'' => self.consume_string_sq(start),
            b'(' => self.consume_single(start, TokenKind::LParen),
            b')' => self.consume_single(start, TokenKind::RParen),
            b'{' => self.consume_single(start, TokenKind::LBrace),
            b'}' => self.consume_single(start, TokenKind::RBrace),
            b'[' => self.consume_single(start, TokenKind::LBracket),
            b']' => self.consume_single(start, TokenKind::RBracket),
            b',' => self.consume_single(start, TokenKind::Comma),
            b';' => self.consume_single(start, TokenKind::Semicolon),
            b'|' => self.consume_single(start, TokenKind::Pipe),
            b'&' => self.consume_single(start, TokenKind::Ampersand),
            b'.' => self.consume_single(start, TokenKind::Dot),
            b'=' => self.consume_single(start, TokenKind::Equals),
            b'+' => self.consume_plus(start),
            b'-' => self.consume_single(start, TokenKind::Minus),
            b'*' => self.consume_single(start, TokenKind::Star),
            b'/' => self.consume_single(start, TokenKind::Slash),
            b'%' => self.consume_single(start, TokenKind::Percent),
            b'`' => self.consume_backtick(start),
            b'0'..=b'9' => self.consume_number(start),
            b if is_ident_start(b) => self.consume_identifier(start),
            _ => self.consume_single(start, TokenKind::Unknown),
        };
        Some(tok)
    }

    fn consume_single(&mut self, start: usize, kind: TokenKind) -> Token {
        let end: usize = start + 1;
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind,
            text,
            start,
            end,
        }
    }

    fn consume_plus(&mut self, start: usize) -> Token {
        if self.peek(1) == Some(b'=') {
            self.pos = start + 2;
            return Token {
                kind: TokenKind::PlusEq,
                text: "+=".to_owned(),
                start,
                end: start + 2,
            };
        }
        self.consume_single(start, TokenKind::Plus)
    }

    fn consume_backtick(&mut self, start: usize) -> Token {
        let end: usize = (start + 2).min(self.scan_end);
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind: TokenKind::Backtick,
            text,
            start,
            end,
        }
    }

    fn consume_whitespace(&mut self, start: usize) -> Token {
        let mut end: usize = start;
        while end < self.scan_end {
            let c: u8 = self.src[end];
            if c == b' ' || c == b'\t' || c == b'\r' {
                end += 1;
            } else {
                break;
            }
        }
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind: TokenKind::Whitespace,
            text,
            start,
            end,
        }
    }

    fn consume_comment(&mut self, start: usize) -> Token {
        let mut end: usize = start;
        while end < self.scan_end && self.src[end] != b'\n' {
            end += 1;
        }
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind: TokenKind::Comment,
            text,
            start,
            end,
        }
    }

    fn consume_variable(&mut self, start: usize) -> Token {
        let mut end: usize = start + 1;
        if end < self.scan_end && self.src[end] == b'{' {
            end += 1;
            while end < self.scan_end && self.src[end] != b'}' {
                end += 1;
            }
            if end < self.scan_end {
                end += 1;
            }
        } else {
            while end < self.scan_end && is_ident_continue(self.src[end]) {
                end += 1;
            }
        }
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind: TokenKind::Variable,
            text,
            start,
            end,
        }
    }

    fn consume_string_dq(&mut self, start: usize) -> Token {
        let mut end: usize = start + 1;
        while end < self.scan_end {
            let c: u8 = self.src[end];
            if c == b'`' && end + 1 < self.scan_end {
                end += 2;
                continue;
            }
            if c == b'"' {
                end += 1;
                break;
            }
            end += 1;
        }
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind: TokenKind::StringDq,
            text,
            start,
            end,
        }
    }

    fn consume_string_sq(&mut self, start: usize) -> Token {
        let mut end: usize = start + 1;
        while end < self.scan_end {
            let c: u8 = self.src[end];
            if c == b'\'' {
                if end + 1 < self.scan_end && self.src[end + 1] == b'\'' {
                    end += 2;
                    continue;
                }
                end += 1;
                break;
            }
            end += 1;
        }
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind: TokenKind::StringSq,
            text,
            start,
            end,
        }
    }

    fn consume_number(&mut self, start: usize) -> Token {
        let mut end: usize = start;
        while end < self.scan_end && self.src[end].is_ascii_digit() {
            end += 1;
        }
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind: TokenKind::Number,
            text,
            start,
            end,
        }
    }

    fn consume_identifier(&mut self, start: usize) -> Token {
        let mut end: usize = start;
        while end < self.scan_end && (is_ident_continue(self.src[end]) || self.src[end] == b'-') {
            end += 1;
        }
        let text: String = token_text(self.src, start, end);
        self.pos = end;
        Token {
            kind: TokenKind::Identifier,
            text,
            start,
            end,
        }
    }

    #[inline]
    fn peek(&self, off: usize) -> Option<u8> {
        let index: usize = self.pos.checked_add(off)?;
        if index >= self.scan_end {
            return None;
        }
        self.src.get(index).copied()
    }
}

fn token_text(src: &[u8], start: usize, end: usize) -> String {
    let bounded_start: usize = start.min(src.len());
    let bounded_end: usize = end.min(src.len()).max(bounded_start);
    let capped_end: usize = bounded_end.min(bounded_start.saturating_add(MAX_TOKEN_SOURCE_BYTES));
    let decoded: String = String::from_utf8_lossy(&src[bounded_start..capped_end]).into_owned();
    decoded.into_boxed_str().into()
}

fn truncate_token_text(text: &mut String, budget: &mut usize) -> bool {
    if text.len() <= *budget {
        *budget = budget.saturating_sub(text.len());
        return false;
    }
    let mut end: usize = (*budget).min(text.len());
    while end > 0usize && !text.is_char_boundary(end) {
        end = end.saturating_sub(1usize);
    }
    let retained: String = text[..end].to_owned();
    *text = retained;
    *budget = 0usize;
    true
}

#[inline]
const fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

#[inline]
const fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn lex_variable_and_string() {
        let src: &[u8] = b"$foo = 'bar'";
        let toks: Vec<Token> = Lexer::new(src).tokenize();
        let kinds: Vec<TokenKind> = toks.iter().map(|t: &Token| t.kind).collect();
        assert!(kinds.contains(&TokenKind::Variable));
        assert!(kinds.contains(&TokenKind::StringSq));
    }

    #[test]
    fn lex_dq_string_with_backtick_escape() {
        let src: &[u8] = b"\"x`\"y\"";
        let toks: Vec<Token> = Lexer::new(src).tokenize();
        let dq: &Token = toks
            .iter()
            .find(|t: &&Token| t.kind == TokenKind::StringDq)
            .expect("dq string");
        assert!(dq.text.starts_with('\"'));
        assert!(dq.text.ends_with('\"'));
    }

    #[test]
    fn lex_curly_variable() {
        let src: &[u8] = b"${foo bar}";
        let toks: Vec<Token> = Lexer::new(src).tokenize();
        let v: &Token = toks
            .iter()
            .find(|t: &&Token| t.kind == TokenKind::Variable)
            .expect("variable");
        assert_eq!(v.text, "${foo bar}");
    }
}
