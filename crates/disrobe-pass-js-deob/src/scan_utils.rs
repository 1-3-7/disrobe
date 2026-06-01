//! Shared string-/comment-aware delimiter scanning over raw JS bytes.
//!
//! These helpers walk balanced `()`, `{}`, `[]` regions while skipping string
//! and template literals and both comment styles, so a `}` inside a string is
//! never mistaken for a block close. Used by bundle extraction and string-array
//! recovery where a regex `[^}]*` body match is unsound on nested input.

/// Index of the `)` that closes the group opened just before `start`
/// (i.e. `start` is the byte after the opening `(`). `None` if unbalanced.
#[must_use]
pub(crate) fn find_paren_close(bytes: &[u8], start: usize) -> Option<usize> {
    find_close(bytes, start, b'(', b')')
}

/// Index of the `}` that closes the block whose body begins at `start`.
#[must_use]
pub(crate) fn find_brace_close(bytes: &[u8], start: usize) -> Option<usize> {
    find_close(bytes, start, b'{', b'}')
}

/// Index one past the closing quote of the string literal whose opening quote
/// is at `start`. Handles backslash escapes. `None` if unterminated.
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
}
