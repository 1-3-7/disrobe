use serde::Serialize;

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
}

impl<'a> Lexer<'a> {
    #[inline]
    #[must_use]
    pub const fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    pub fn tokenize(mut self) -> Vec<Token> {
        let mut out: Vec<Token> = Vec::with_capacity(self.src.len() / 4 + 8);
        while let Some(tok) = self.next_token() {
            if tok.kind == TokenKind::Eof {
                out.push(tok);
                break;
            }
            out.push(tok);
        }
        out
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.pos >= self.src.len() {
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
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        let end: usize = (start + 2).min(self.src.len());
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        while end < self.src.len() {
            let c: u8 = self.src[end];
            if c == b' ' || c == b'\t' || c == b'\r' {
                end += 1;
            } else {
                break;
            }
        }
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        while end < self.src.len() && self.src[end] != b'\n' {
            end += 1;
        }
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        if end < self.src.len() && self.src[end] == b'{' {
            end += 1;
            while end < self.src.len() && self.src[end] != b'}' {
                end += 1;
            }
            if end < self.src.len() {
                end += 1;
            }
        } else {
            while end < self.src.len() && is_ident_continue(self.src[end]) {
                end += 1;
            }
        }
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        while end < self.src.len() {
            let c: u8 = self.src[end];
            if c == b'`' && end + 1 < self.src.len() {
                end += 2;
                continue;
            }
            if c == b'"' {
                end += 1;
                break;
            }
            end += 1;
        }
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        while end < self.src.len() {
            let c: u8 = self.src[end];
            if c == b'\'' {
                if end + 1 < self.src.len() && self.src[end + 1] == b'\'' {
                    end += 2;
                    continue;
                }
                end += 1;
                break;
            }
            end += 1;
        }
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        while end < self.src.len() && self.src[end].is_ascii_digit() {
            end += 1;
        }
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        while end < self.src.len() && (is_ident_continue(self.src[end]) || self.src[end] == b'-') {
            end += 1;
        }
        let text: String = String::from_utf8_lossy(&self.src[start..end]).into_owned();
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
        self.src.get(self.pos + off).copied()
    }
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
