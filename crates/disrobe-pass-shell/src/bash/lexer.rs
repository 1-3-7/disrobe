use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BashTokenKind {
    Word,
    Variable,
    StringDq,
    StringSq,
    Subst,
    LBrace,
    RBrace,
    LParen,
    RParen,
    Pipe,
    Semicolon,
    AmpAmp,
    PipePipe,
    Redir,
    Heredoc,
    Newline,
    Whitespace,
    Comment,
    Backslash,
    Eof,
}

#[derive(Debug, Clone, Serialize)]
pub struct BashToken {
    pub kind: BashTokenKind,
    pub text: String,
    pub start: usize,
    pub end: usize,
}

#[must_use]
pub fn tokenize_bash(src: &[u8]) -> Vec<BashToken> {
    let mut out: Vec<BashToken> = Vec::with_capacity(src.len() / 4 + 4);
    let mut pos: usize = 0;
    while pos < src.len() {
        let start: usize = pos;
        let b: u8 = src[pos];
        let tok: BashToken = match b {
            b' ' | b'\t' => consume_run(src, &mut pos, BashTokenKind::Whitespace, |c: u8| {
                c == b' ' || c == b'\t'
            }),
            b'\n' => single(src, &mut pos, BashTokenKind::Newline),
            b'\r' => single(src, &mut pos, BashTokenKind::Whitespace),
            b'#' => consume_until(src, &mut pos, BashTokenKind::Comment, b'\n'),
            b'$' => consume_variable(src, &mut pos),
            b'"' => consume_string(src, &mut pos, b'"', BashTokenKind::StringDq),
            b'\'' => consume_string(src, &mut pos, b'\'', BashTokenKind::StringSq),
            b'(' => single(src, &mut pos, BashTokenKind::LParen),
            b')' => single(src, &mut pos, BashTokenKind::RParen),
            b'{' => single(src, &mut pos, BashTokenKind::LBrace),
            b'}' => single(src, &mut pos, BashTokenKind::RBrace),
            b'|' => {
                if src.get(pos + 1) == Some(&b'|') {
                    let end: usize = pos + 2;
                    let text: String = String::from_utf8_lossy(&src[pos..end]).into_owned();
                    pos = end;
                    BashToken {
                        kind: BashTokenKind::PipePipe,
                        text,
                        start,
                        end,
                    }
                } else {
                    single(src, &mut pos, BashTokenKind::Pipe)
                }
            }
            b'&' => {
                if src.get(pos + 1) == Some(&b'&') {
                    let end: usize = pos + 2;
                    let text: String = String::from_utf8_lossy(&src[pos..end]).into_owned();
                    pos = end;
                    BashToken {
                        kind: BashTokenKind::AmpAmp,
                        text,
                        start,
                        end,
                    }
                } else {
                    single(src, &mut pos, BashTokenKind::Redir)
                }
            }
            b';' => single(src, &mut pos, BashTokenKind::Semicolon),
            b'<' | b'>' => single(src, &mut pos, BashTokenKind::Redir),
            b'\\' => single(src, &mut pos, BashTokenKind::Backslash),
            _ => consume_word(src, &mut pos),
        };
        out.push(tok);
    }
    out.push(BashToken {
        kind: BashTokenKind::Eof,
        text: String::new(),
        start: pos,
        end: pos,
    });
    out
}

fn single(src: &[u8], pos: &mut usize, kind: BashTokenKind) -> BashToken {
    let start: usize = *pos;
    let end: usize = start + 1;
    let text: String = String::from_utf8_lossy(&src[start..end]).into_owned();
    *pos = end;
    BashToken {
        kind,
        text,
        start,
        end,
    }
}

fn consume_run<F>(src: &[u8], pos: &mut usize, kind: BashTokenKind, pred: F) -> BashToken
where
    F: Fn(u8) -> bool,
{
    let start: usize = *pos;
    let mut end: usize = start;
    while end < src.len() && pred(src[end]) {
        end += 1;
    }
    let text: String = String::from_utf8_lossy(&src[start..end]).into_owned();
    *pos = end;
    BashToken {
        kind,
        text,
        start,
        end,
    }
}

fn consume_until(src: &[u8], pos: &mut usize, kind: BashTokenKind, stop: u8) -> BashToken {
    let start: usize = *pos;
    let mut end: usize = start;
    while end < src.len() && src[end] != stop {
        end += 1;
    }
    let text: String = String::from_utf8_lossy(&src[start..end]).into_owned();
    *pos = end;
    BashToken {
        kind,
        text,
        start,
        end,
    }
}

fn consume_variable(src: &[u8], pos: &mut usize) -> BashToken {
    let start: usize = *pos;
    let mut end: usize = start + 1;
    if end < src.len() && src[end] == b'{' {
        while end < src.len() && src[end] != b'}' {
            end += 1;
        }
        if end < src.len() {
            end += 1;
        }
    } else if end < src.len() && src[end] == b'(' {
        let mut depth: usize = 0;
        while end < src.len() {
            if src[end] == b'(' {
                depth += 1;
            } else if src[end] == b')' {
                depth -= 1;
                if depth == 0 {
                    end += 1;
                    break;
                }
            }
            end += 1;
        }
        let text: String = String::from_utf8_lossy(&src[start..end]).into_owned();
        *pos = end;
        return BashToken {
            kind: BashTokenKind::Subst,
            text,
            start,
            end,
        };
    } else {
        while end < src.len()
            && (src[end].is_ascii_alphanumeric()
                || src[end] == b'_'
                || src[end] == b'?'
                || src[end] == b'#')
        {
            end += 1;
        }
    }
    let text: String = String::from_utf8_lossy(&src[start..end]).into_owned();
    *pos = end;
    BashToken {
        kind: BashTokenKind::Variable,
        text,
        start,
        end,
    }
}

fn consume_string(src: &[u8], pos: &mut usize, q: u8, kind: BashTokenKind) -> BashToken {
    let start: usize = *pos;
    let mut end: usize = start + 1;
    while end < src.len() {
        let c: u8 = src[end];
        if c == b'\\' && end + 1 < src.len() {
            end += 2;
            continue;
        }
        if c == q {
            end += 1;
            break;
        }
        end += 1;
    }
    let text: String = String::from_utf8_lossy(&src[start..end]).into_owned();
    *pos = end;
    BashToken {
        kind,
        text,
        start,
        end,
    }
}

fn consume_word(src: &[u8], pos: &mut usize) -> BashToken {
    let start: usize = *pos;
    let mut end: usize = start;
    while end < src.len() {
        let c: u8 = src[end];
        if matches!(
            c,
            b' ' | b'\t'
                | b'\n'
                | b'\r'
                | b'\\'
                | b'|'
                | b'&'
                | b';'
                | b'<'
                | b'>'
                | b'('
                | b')'
                | b'{'
                | b'}'
                | b'#'
                | b'"'
                | b'\''
                | b'$'
        ) {
            break;
        }
        end += 1;
    }
    if end == start {
        end += 1;
    }
    let text: String = String::from_utf8_lossy(&src[start..end]).into_owned();
    *pos = end;
    BashToken {
        kind: BashTokenKind::Word,
        text,
        start,
        end,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenises_basic_pipeline() {
        let src: &[u8] = b"echo hi | base64 -d\n";
        let toks: Vec<BashToken> = tokenize_bash(src);
        assert!(
            toks.iter()
                .any(|t: &BashToken| t.kind == BashTokenKind::Pipe)
        );
        assert!(
            toks.iter()
                .any(|t: &BashToken| t.kind == BashTokenKind::Word)
        );
    }

    #[test]
    fn tokenises_command_substitution() {
        let src: &[u8] = b"$(echo nested)";
        let toks: Vec<BashToken> = tokenize_bash(src);
        let subst: Option<&BashToken> = toks
            .iter()
            .find(|t: &&BashToken| t.kind == BashTokenKind::Subst);
        assert!(subst.is_some());
    }
}
