use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct NormalizeReport {
    pub caret_escapes_removed: usize,
    pub line_continuations_joined: usize,
    pub output: String,
}

#[must_use]
pub fn normalize(input: &str) -> NormalizeReport {
    let joined: (String, usize) = join_continuations(input);
    let stripped: (String, usize) = strip_carets(&joined.0);
    NormalizeReport {
        caret_escapes_removed: stripped.1,
        line_continuations_joined: joined.1,
        output: stripped.0,
    }
}

fn join_continuations(input: &str) -> (String, usize) {
    let normalised: String = input.replace("\r\n", "\n").replace('\r', "\n");
    let mut out: String = String::with_capacity(normalised.len());
    let mut joins: usize = 0;
    let bytes: &[u8] = normalised.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'^' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' && !is_escaped(bytes, i) {
            joins += 1;
            i += 2;
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    (out, joins)
}

fn strip_carets(input: &str) -> (String, usize) {
    let mut out: String = String::with_capacity(input.len());
    let mut removed: usize = 0;
    let chars: Vec<char> = input.chars().collect();
    let mut i: usize = 0;
    let mut in_double_quote: bool = false;
    while i < chars.len() {
        let c: char = chars[i];
        if c == '"' {
            in_double_quote = !in_double_quote;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '^' && !in_double_quote {
            if let Some(&next) = chars.get(i + 1) {
                if next == '^' {
                    out.push('^');
                    removed += 1;
                    i += 2;
                    continue;
                }
                removed += 1;
                out.push(next);
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    (out, removed)
}

fn is_escaped(bytes: &[u8], idx: usize) -> bool {
    let mut count: usize = 0;
    let mut j: isize = idx as isize - 1;
    while j >= 0 && bytes[j as usize] == b'^' {
        count += 1;
        j -= 1;
    }
    count % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_inline_carets() {
        let r: NormalizeReport = normalize("@e^cho o^ff\n");
        assert_eq!(r.output, "@echo off\n");
        assert!(r.caret_escapes_removed >= 2);
    }

    #[test]
    fn joins_caret_line_continuation() {
        let r: NormalizeReport = normalize("echo a^\nb\n");
        assert_eq!(r.output, "echo ab\n");
        assert_eq!(r.line_continuations_joined, 1);
    }

    #[test]
    fn preserves_carets_inside_quotes() {
        let r: NormalizeReport = normalize("echo \"a^b\"\n");
        assert_eq!(r.output, "echo \"a^b\"\n");
    }

    #[test]
    fn escaped_caret_becomes_single() {
        let r: NormalizeReport = normalize("echo a^^b\n");
        assert_eq!(r.output, "echo a^b\n");
    }
}
