#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shebang {
    pub line: String,
    pub interpreter_hint: Option<String>,
    pub body_offset: usize,
}

#[must_use]
pub fn parse(bytes: &[u8]) -> Option<Shebang> {
    if bytes.len() < 2 || &bytes[..2] != b"#!" {
        return None;
    }
    let mut end: usize = bytes.len();
    for (i, b) in bytes.iter().enumerate().take(4096) {
        if *b == b'\n' {
            end = i;
            break;
        }
    }
    let line_bytes: &[u8] = &bytes[..end];
    let line: String = String::from_utf8_lossy(line_bytes).into_owned();
    let interpreter_hint: Option<String> = line
        .strip_prefix("#!")
        .map(|tail| tail.trim().to_owned())
        .filter(|s| !s.is_empty());
    let body_offset: usize = if end < bytes.len() { end + 1 } else { end };
    Some(Shebang {
        line,
        interpreter_hint,
        body_offset,
    })
}

#[must_use]
pub fn looks_like_python_runner(line: &str) -> bool {
    let l: String = line.to_ascii_lowercase();
    l.contains("python") || l.contains("py3") || l.contains("/usr/bin/env python")
}

#[allow(dead_code)]
pub(crate) fn body<'a>(bytes: &'a [u8], hdr: &Shebang) -> &'a [u8] {
    let off: usize = hdr.body_offset.min(bytes.len());
    &bytes[off..]
}

#[allow(dead_code)]
pub(crate) fn checked_drain(bytes: &[u8]) -> &[u8] {
    parse(bytes).map_or(bytes, |hdr| &bytes[hdr.body_offset..])
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_python_shebang() {
        let buf: &[u8] = b"#!/usr/bin/env python3\nbody\n";
        let hdr: Shebang = parse(buf).expect("shebang must parse");
        assert_eq!(hdr.line, "#!/usr/bin/env python3");
        assert_eq!(
            hdr.interpreter_hint.as_deref(),
            Some("/usr/bin/env python3")
        );
        assert_eq!(hdr.body_offset, 23);
        assert!(looks_like_python_runner(&hdr.line));
    }

    #[test]
    fn returns_none_without_marker() {
        assert!(parse(b"PK\x03\x04whatever").is_none());
    }

    #[test]
    fn handles_eof_without_newline() {
        let hdr: Shebang = parse(b"#!/usr/local/bin/python").expect("shebang parse");
        assert_eq!(hdr.body_offset, 23);
    }
}
