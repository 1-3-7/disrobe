use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct IntegrityStripStats {
    pub iifes_stripped: usize,
    pub bare_loops_stripped: usize,
    pub bytes_removed: usize,
}

pub fn strip_integrity_loops(source: &str) -> (String, IntegrityStripStats) {
    let mut stats: IntegrityStripStats = IntegrityStripStats::default();
    let after_iife: String = strip_integrity_iifes(source, &mut stats);
    let after_bare: String = strip_bare_integrity_loops(&after_iife, &mut stats);
    stats.bytes_removed = source.len().saturating_sub(after_bare.len());
    (after_bare, stats)
}

fn strip_integrity_iifes(source: &str, stats: &mut IntegrityStripStats) -> String {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len());
    let mut i: usize = 0;
    let mut cursor: usize = 0;
    while i < bytes.len() {
        if let Some(end) = match_integrity_iife(source, i) {
            out.push_str(&source[cursor..i]);
            cursor = end;
            stats.iifes_stripped += 1;
            i = end;
            continue;
        }
        i += 1;
    }
    out.push_str(&source[cursor..]);
    out
}

fn strip_bare_integrity_loops(source: &str, stats: &mut IntegrityStripStats) -> String {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len());
    let mut i: usize = 0;
    let mut cursor: usize = 0;
    while i < bytes.len() {
        if let Some(end) = match_integrity_loop(source, i) {
            out.push_str(&source[cursor..i]);
            cursor = end;
            stats.bare_loops_stripped += 1;
            i = end;
            continue;
        }
        i += 1;
    }
    out.push_str(&source[cursor..]);
    out
}

fn match_integrity_iife(source: &str, start: usize) -> Option<usize> {
    let bytes: &[u8] = source.as_bytes();
    if bytes.get(start)? != &b'(' {
        return None;
    }
    let mut i: usize = start + 1;
    i = skip_ws(bytes, i);
    if !slice_eq(bytes, i, b"function") {
        return None;
    }
    i += b"function".len();
    i = skip_ws(bytes, i);
    if bytes.get(i)? != &b'(' {
        return None;
    }
    let paren_close: usize = find_paren_close(bytes, i + 1)?;
    let body_open: usize = skip_ws(bytes, paren_close + 1);
    if bytes.get(body_open)? != &b'{' {
        return None;
    }
    let body_close: usize = find_brace_close(bytes, body_open + 1)?;
    let body_text: &str = source.get(body_open + 1..body_close)?;
    if !is_integrity_loop_body(body_text) {
        return None;
    }
    let mut tail: usize = body_close + 1;
    tail = skip_ws(bytes, tail);
    let invocation_inside_paren: bool = bytes.get(tail) == Some(&b'(');
    if invocation_inside_paren {
        if !slice_eq(bytes, tail, b"()") {
            return None;
        }
        tail += 2;
        tail = skip_ws(bytes, tail);
        if bytes.get(tail)? != &b')' {
            return None;
        }
        tail += 1;
    } else {
        if bytes.get(tail)? != &b')' {
            return None;
        }
        tail += 1;
        tail = skip_ws(bytes, tail);
        if !slice_eq(bytes, tail, b"()") {
            return None;
        }
        tail += 2;
    }
    if bytes.get(tail) == Some(&b';') {
        tail += 1;
    }
    Some(tail)
}

fn match_integrity_loop(source: &str, start: usize) -> Option<usize> {
    let bytes: &[u8] = source.as_bytes();
    if start > 0 {
        let prev: u8 = bytes.get(start - 1).copied().unwrap_or(b' ');
        if matches!(prev, b'_' | b'$') || prev.is_ascii_alphanumeric() {
            return None;
        }
    }
    let head: &[u8] = bytes.get(start..)?;
    let header_len: usize = if head.starts_with(b"while") {
        5
    } else if head.starts_with(b"for") {
        3
    } else {
        return None;
    };
    let mut i: usize = start + header_len;
    i = skip_ws(bytes, i);
    if bytes.get(i)? != &b'(' {
        return None;
    }
    let paren_close: usize = find_paren_close(bytes, i + 1)?;
    let cond_text: &str = source.get(i + 1..paren_close)?.trim();
    if !matches!(cond_text, "!![]" | "true" | "1") {
        return None;
    }
    let body_open: usize = skip_ws(bytes, paren_close + 1);
    if bytes.get(body_open)? != &b'{' {
        return None;
    }
    let body_close: usize = find_brace_close(bytes, body_open + 1)?;
    let body_text: &str = source.get(body_open + 1..body_close)?;
    if !body_text.contains("[]") || !body_text.contains("constructor") {
        return None;
    }
    let mut tail: usize = body_close + 1;
    if bytes.get(tail) == Some(&b';') {
        tail += 1;
    }
    Some(tail)
}

fn is_integrity_loop_body(text: &str) -> bool {
    let has_while: bool = text.contains("while") || text.contains("for");
    let has_self_call: bool =
        text.contains("[]") && (text.contains("constructor") || text.contains("toString"));
    has_while && has_self_call
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

fn slice_eq(bytes: &[u8], start: usize, needle: &[u8]) -> bool {
    bytes
        .get(start..start + needle.len())
        .is_some_and(|s| s == needle)
}

fn find_paren_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn find_brace_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn skip_string(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn strips_integrity_iife() {
        let src: &str = "var x = 1;\n(function () { while (!![]) { var y = []['constructor']; } }());\nconsole.log(x);";
        let (out, stats): (String, IntegrityStripStats) = strip_integrity_loops(src);
        assert_eq!(
            stats.iifes_stripped, 1,
            "iife not stripped; out={out:?} stats={stats:?}"
        );
        assert!(!out.contains("while (!![])"));
        assert!(out.contains("console.log(x)"));
    }

    #[test]
    fn strips_bare_integrity_loop() {
        let src: &str = "var x = 1;\nwhile (!![]) { var y = []['constructor']; }\nconsole.log(x);";
        let (out, stats): (String, IntegrityStripStats) = strip_integrity_loops(src);
        assert_eq!(stats.bare_loops_stripped, 1);
        assert!(!out.contains("while (!![])"));
    }

    #[test]
    fn preserves_unrelated_loops() {
        let src: &str = "while (i < 10) { i = i + 1; }";
        let (out, stats): (String, IntegrityStripStats) = strip_integrity_loops(src);
        assert_eq!(out, src);
        assert_eq!(stats.bare_loops_stripped, 0);
    }
}
