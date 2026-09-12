use serde::Serialize;

const MAX_TOKEN_COUNT: usize = 65_536usize;
const MAX_TOKEN_TEXT_BYTES: usize = 65_536usize;
const MAX_TOKEN_SOURCE_BYTES: usize = MAX_TOKEN_TEXT_BYTES / 3usize;
const MAX_TOTAL_TOKEN_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_LEXER_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SUBSTITUTION_DEPTH: usize = 256usize;

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
    Truncated,
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
    let source_len: usize = src.len();
    let visible_len: usize = source_len.min(MAX_LEXER_INPUT_BYTES);
    let src: &[u8] = &src[..visible_len];
    let initial_capacity: usize = (src.len() / 4usize)
        .saturating_add(4usize)
        .min(MAX_TOKEN_COUNT.saturating_add(1usize));
    let mut out: Vec<BashToken> = Vec::with_capacity(initial_capacity);
    let mut pos: usize = 0;
    let mut text_budget: usize = MAX_TOTAL_TOKEN_TEXT_BYTES;
    let mut truncation: Option<(usize, usize)> =
        (visible_len < source_len).then_some((visible_len, source_len));
    while pos < src.len() && out.len() < MAX_TOKEN_COUNT {
        let start: usize = pos;
        let b: u8 = src[pos];
        let mut nesting_truncated: bool = false;
        let mut tok: BashToken = match b {
            b' ' | b'\t' => consume_run(src, &mut pos, BashTokenKind::Whitespace, |c: u8| {
                c == b' ' || c == b'\t'
            }),
            b'\n' => single(src, &mut pos, BashTokenKind::Newline),
            b'\r' => single(src, &mut pos, BashTokenKind::Whitespace),
            b'#' => consume_until(src, &mut pos, BashTokenKind::Comment, b'\n'),
            b'$' => consume_variable(src, &mut pos, &mut nesting_truncated),
            b'"' => consume_string(src, &mut pos, b'"', BashTokenKind::StringDq),
            b'\'' => consume_string(src, &mut pos, b'\'', BashTokenKind::StringSq),
            b'(' => single(src, &mut pos, BashTokenKind::LParen),
            b')' => single(src, &mut pos, BashTokenKind::RParen),
            b'{' => single(src, &mut pos, BashTokenKind::LBrace),
            b'}' => single(src, &mut pos, BashTokenKind::RBrace),
            b'|' => {
                if src.get(pos + 1) == Some(&b'|') {
                    let end: usize = pos + 2;
                    let text: String = token_text(src, pos, end);
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
                    let text: String = token_text(src, pos, end);
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
        let source_limit_exceeded: bool =
            tok.end.saturating_sub(tok.start) > MAX_TOKEN_SOURCE_BYTES;
        let text_budget_exceeded: bool = truncate_token_text(&mut tok.text, &mut text_budget);
        let token_truncated: bool =
            nesting_truncated || source_limit_exceeded || text_budget_exceeded;
        if token_truncated && truncation.is_none() {
            truncation = Some((tok.start, source_len));
        }
        out.push(tok);
        if token_truncated {
            break;
        }
    }
    if pos < src.len() && truncation.is_none() {
        truncation = Some((pos, src.len()));
    }
    if let Some((start, end)) = truncation {
        out.push(BashToken {
            kind: BashTokenKind::Truncated,
            text: String::new(),
            start,
            end,
        });
    }
    out.push(BashToken {
        kind: BashTokenKind::Eof,
        text: String::new(),
        start: source_len,
        end: source_len,
    });
    out
}

fn single(src: &[u8], pos: &mut usize, kind: BashTokenKind) -> BashToken {
    let start: usize = *pos;
    let end: usize = start + 1;
    let text: String = token_text(src, start, end);
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
    let text: String = token_text(src, start, end);
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
    let text: String = token_text(src, start, end);
    *pos = end;
    BashToken {
        kind,
        text,
        start,
        end,
    }
}

fn consume_variable(src: &[u8], pos: &mut usize, nesting_truncated: &mut bool) -> BashToken {
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
                let Some(next_depth): Option<usize> = depth.checked_add(1usize) else {
                    *nesting_truncated = true;
                    break;
                };
                if next_depth > MAX_SUBSTITUTION_DEPTH {
                    *nesting_truncated = true;
                    break;
                }
                depth = next_depth;
            } else if src[end] == b')' {
                let Some(next_depth): Option<usize> = depth.checked_sub(1usize) else {
                    *nesting_truncated = true;
                    break;
                };
                depth = next_depth;
                if depth == 0 {
                    end += 1;
                    break;
                }
            }
            end += 1;
        }
        let text: String = token_text(src, start, end);
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
    let text: String = token_text(src, start, end);
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
    let text: String = token_text(src, start, end);
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
    let text: String = token_text(src, start, end);
    *pos = end;
    BashToken {
        kind: BashTokenKind::Word,
        text,
        start,
        end,
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
