use core::ops::Range;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{
    apply_splice_edits, boundary_after, boundary_before, skip_string_literal, skip_ws, slice_eq,
};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    scan(source).0
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let (count, edits): (usize, Vec<(Range<usize>, Option<String>)>) = scan(source);
    let mut stats: TransformStats = TransformStats {
        matched: count,
        ..TransformStats::default()
    };
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let mut edits_mut: Vec<(Range<usize>, Option<String>)> = edits;
    let (rewritten, applied): (String, usize) = apply_splice_edits(source, &mut edits_mut);
    stats.reversed = applied;
    TransformOutput {
        source: rewritten,
        stats,
    }
}

fn scan(source: &str) -> (usize, Vec<(Range<usize>, Option<String>)>) {
    let bytes: &[u8] = source.as_bytes();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'\'' | b'"' | b'`') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            i = end;
            continue;
        }
        let kw: Option<&'static [u8]> = if slice_eq(bytes, i, b"var")
            && boundary_before(bytes, i)
            && boundary_after(bytes, i + 3)
        {
            Some(b"var")
        } else if slice_eq(bytes, i, b"let")
            && boundary_before(bytes, i)
            && boundary_after(bytes, i + 3)
        {
            Some(b"let")
        } else if slice_eq(bytes, i, b"const")
            && boundary_before(bytes, i)
            && boundary_after(bytes, i + 5)
        {
            Some(b"const")
        } else {
            None
        };
        let Some(kw_bytes): Option<&'static [u8]> = kw else {
            i += 1;
            continue;
        };
        let kw_len: usize = kw_bytes.len();
        let after_kw: usize = skip_ws(bytes, i + kw_len);
        let Some(stmt_end): Option<usize> = find_statement_terminator(bytes, after_kw) else {
            i += 1;
            continue;
        };
        let body: &str = match source.get(after_kw..stmt_end) {
            Some(s) => s,
            None => {
                i += 1;
                continue;
            }
        };
        let parts: Vec<&str> = split_top_level_commas(body);
        if parts.len() < 2 {
            i = stmt_end + 1;
            continue;
        }
        let kw_text: &str = match core::str::from_utf8(kw_bytes) {
            Ok(s) => s,
            Err(_) => {
                i += 1;
                continue;
            }
        };
        let mut rewritten: String = String::with_capacity(body.len() + parts.len() * 8);
        for (idx, part) in parts.iter().enumerate() {
            if idx > 0 {
                rewritten.push('\n');
            }
            rewritten.push_str(kw_text);
            rewritten.push(' ');
            rewritten.push_str(part.trim());
            rewritten.push(';');
        }
        let final_end: usize = if bytes.get(stmt_end) == Some(&b';') {
            stmt_end + 1
        } else {
            stmt_end
        };
        edits.push((i..final_end, Some(rewritten)));
        count += 1;
        i = final_end;
    }
    (count, edits)
}

fn find_statement_terminator(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, b)?;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' if brace == 0 => return Some(i),
            b'}' => brace -= 1,
            b';' if paren == 0 && bracket == 0 && brace == 0 => return Some(i),
            b'\n' if paren == 0 && bracket == 0 && brace == 0 => {
                let next: usize = skip_ws(bytes, i + 1);
                if bytes.get(next).is_some_and(|c: &u8| !matches!(c, b',')) {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Some(i)
}

fn split_top_level_commas(text: &str) -> Vec<&str> {
    let bytes: &[u8] = text.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start: usize = 0;
    let mut i: usize = 0;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                    return Vec::new();
                };
                i = end;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b',' if paren == 0 && bracket == 0 && brace == 0 => {
                out.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&text[start..]);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_grouped_var_decl() {
        let src: &str = "var a = 1, b = 2, c = 3;";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn splits_grouped_var_into_per_var_lines() {
        let src: &str = "var a = 1, b = 2, c = 3;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("var a = 1;"));
        assert!(out.source.contains("var b = 2;"));
        assert!(out.source.contains("var c = 3;"));
    }

    #[test]
    fn splits_grouped_let_decl() {
        let src: &str = "let a = 1, b = 2;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("let a = 1;"));
        assert!(out.source.contains("let b = 2;"));
    }

    #[test]
    fn no_op_on_single_decl() {
        let src: &str = "var x = 1;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
