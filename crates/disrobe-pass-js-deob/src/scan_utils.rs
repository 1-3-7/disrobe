#[must_use]
pub(crate) fn head(text: &str, max_bytes: usize) -> &str {
    let mut end: usize = text.len().min(max_bytes);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[must_use]
pub(crate) fn find_paren_close(bytes: &[u8], start: usize) -> Option<usize> {
    find_close(bytes, start, b'(', b')')
}

#[must_use]
pub(crate) fn find_brace_close(bytes: &[u8], start: usize) -> Option<usize> {
    find_close(bytes, start, b'{', b'}')
}

#[must_use]
pub(crate) fn skip_ws(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

#[must_use]
pub(crate) fn find_statement_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, b)?;
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = i.saturating_add(2);
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b';' if paren == 0 && bracket == 0 && brace == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

#[must_use]
pub(crate) const fn regex_can_follow(prev: u8) -> bool {
    matches!(
        prev,
        b'(' | b','
            | b'='
            | b':'
            | b'['
            | b'!'
            | b'&'
            | b'|'
            | b'?'
            | b'{'
            | b'}'
            | b';'
            | b'+'
            | b'-'
            | b'*'
            | b'%'
            | b'<'
            | b'>'
            | b'~'
            | b'^'
            | b'\n'
            | b'\r'
    )
}

#[must_use]
pub(crate) fn skip_regex_literal(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 1;
    let mut in_class: bool = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'[' => {
                in_class = true;
                i += 1;
            }
            b']' => {
                in_class = false;
                i += 1;
            }
            b'/' if !in_class => {
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
                {
                    i += 1;
                }
                return i;
            }
            b'\n' => return start + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

#[must_use]
pub(crate) fn skip_string(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut i: usize = start + 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == quote {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

fn find_close(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        } else if b == b'\'' || b == b'"' || b == b'`' {
            i = skip_string(bytes, i, b)?;
            continue;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = i.saturating_add(2);
            continue;
        }
        i += 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn matches_nested_braces() {
        let s: &[u8] = b"{ a { b } c }X";
        let close: usize = find_brace_close(s, 1).expect("balanced");
        assert_eq!(s[close], b'}');
        assert_eq!(close, s.len() - 2);
    }

    #[test]
    fn brace_inside_string_is_ignored() {
        let s: &[u8] = b"{ var x = '}}}}'; }";
        let close: usize = find_brace_close(s, 1).expect("balanced");
        assert_eq!(close, s.len() - 1);
    }

    #[test]
    fn brace_inside_line_comment_is_ignored() {
        let s: &[u8] = b"{ // }}}}\n }";
        let close: usize = find_brace_close(s, 1).expect("balanced");
        assert_eq!(close, s.len() - 1);
    }

    #[test]
    fn paren_with_escaped_quote() {
        let s: &[u8] = b"(f('\\)'))";
        let close: usize = find_paren_close(s, 1).expect("balanced");
        assert_eq!(close, s.len() - 1);
    }

    #[test]
    fn unbalanced_returns_none() {
        assert!(find_brace_close(b"{ a { b }", 1).is_none());
    }

    #[test]
    fn head_clamps_to_char_boundary() {
        let s: &str = "abcé";
        assert_eq!(head(s, 100), "abcé");
        assert_eq!(head(s, 5), "abcé");
        assert_eq!(head(s, 4), "abc");
        assert_eq!(head(s, 3), "abc");
        assert_eq!(head(s, 0), "");
    }

    #[test]
    fn head_never_panics_when_cap_splits_a_multibyte_run() {
        let s: String = "\u{20ac}".repeat(2000);
        let h: &str = head(&s, 4096);
        assert!(h.len() <= 4096);
        assert!(h.len() > 4096 - 4);
        assert!(s.is_char_boundary(h.len()));
    }
}
