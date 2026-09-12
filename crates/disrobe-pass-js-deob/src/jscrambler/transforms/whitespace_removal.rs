use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::skip_string_literal;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    usize::from(is_dense_single_line(source))
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let mut stats: TransformStats = TransformStats::default();
    if !is_dense_single_line(source) {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    stats.matched = 1;
    let formatted: String = beautify(source);
    if formatted == source {
        stats.skipped = 1;
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    stats.reversed = 1;
    TransformOutput {
        source: formatted,
        stats,
    }
}

fn is_dense_single_line(source: &str) -> bool {
    let total: usize = source.len();
    if total < 200 {
        return false;
    }
    let newlines: usize = source.bytes().filter(|b: &u8| *b == b'\n').count();
    let avg_line: usize = if newlines == 0 {
        total
    } else {
        total / (newlines + 1)
    };
    avg_line > 200
}

fn beautify(source: &str) -> String {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len() + source.len() / 4);
    let mut indent: usize = 0;
    let mut i: usize = 0;
    let mut prev_non_ws: u8 = 0;
    let mut at_line_start: bool = true;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'\'' | b'"' | b'`') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                out.push_str(&source[i..]);
                return out;
            };
            if at_line_start {
                push_indent(&mut out, indent);
                at_line_start = false;
            }
            out.push_str(&source[i..end]);
            prev_non_ws = bytes[end - 1];
            i = end;
            continue;
        }
        match b {
            b'{' => {
                if at_line_start {
                    push_indent(&mut out, indent);
                }
                if !out.ends_with(' ') && !out.ends_with('\n') && !out.is_empty() {
                    out.push(' ');
                }
                out.push('{');
                out.push('\n');
                indent += 1;
                at_line_start = true;
                prev_non_ws = b'{';
                i += 1;
                continue;
            }
            b'}' => {
                if !at_line_start {
                    out.push('\n');
                }
                indent = indent.saturating_sub(1);
                push_indent(&mut out, indent);
                out.push('}');
                prev_non_ws = b'}';
                i += 1;
                if bytes.get(i) == Some(&b',') || bytes.get(i) == Some(&b';') {
                    out.push(bytes[i] as char);
                    prev_non_ws = bytes[i];
                    i += 1;
                }
                out.push('\n');
                at_line_start = true;
                continue;
            }
            b';' => {
                if at_line_start {
                    push_indent(&mut out, indent);
                }
                out.push(';');
                out.push('\n');
                at_line_start = true;
                prev_non_ws = b';';
                i += 1;
                continue;
            }
            b'\n' | b'\r' => {
                i += 1;
                continue;
            }
            b' ' | b'\t' => {
                if !at_line_start && !out.ends_with(' ') && !out.ends_with('\n') {
                    out.push(' ');
                }
                i += 1;
                continue;
            }
            _ => {
                if at_line_start {
                    push_indent(&mut out, indent);
                    at_line_start = false;
                }
                out.push(b as char);
                prev_non_ws = b;
                i += 1;
            }
        }
    }
    let _ = prev_non_ws;
    out
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_dense_single_line_blob() {
        let src: String = "function f(){var a=1;var b=2;return a+b;}".repeat(20);
        assert!(detect(&src) >= 1);
    }

    #[test]
    fn beautifies_minified_function() {
        let src: String = "function f(){var a=1;var b=2;return a+b;}".repeat(20);
        let out: TransformOutput = reverse(&src, &TransformOpts::default());
        assert!(out.source.matches('\n').count() > 5);
    }

    #[test]
    fn no_op_on_already_formatted() {
        let src: &str = "function f() {\n  var a = 1;\n  return a;\n}\n";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
