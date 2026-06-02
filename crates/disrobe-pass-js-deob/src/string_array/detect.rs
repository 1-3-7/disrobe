use regex::Regex;

#[derive(Debug, Clone)]
pub(super) struct StringArrayFound {
    pub(super) array_id: String,
    pub(super) literals: Vec<String>,
    pub(super) decl_range: std::ops::Range<usize>,
}

#[derive(Debug, Clone)]
pub(super) struct RotatorFound {
    pub(super) pivot_index: usize,
    pub(super) pivot_value: i64,
    pub(super) iife_range: std::ops::Range<usize>,
}

pub(super) fn find_string_array(source: &str) -> Option<StringArrayFound> {
    let decl_re: Regex = Regex::new(
        r"(?ms)^(?:var|let|const)\s+(_?0x[0-9a-fA-F]+|[a-zA-Z_]\w*)\s*=\s*\[([^\]]*)\]\s*;",
    )
    .ok()?;
    let cap: regex::Captures<'_> = decl_re.captures(source)?;
    let array_id: String = cap.get(1)?.as_str().to_owned();
    let body: &str = cap.get(2)?.as_str();
    let literals: Vec<String> = parse_string_literals(body)?;
    let whole: regex::Match<'_> = cap.get(0)?;
    Some(StringArrayFound {
        array_id,
        literals,
        decl_range: whole.start()..whole.end(),
    })
}

pub(super) fn find_rotator(source: &str, array_id: &str) -> Option<RotatorFound> {
    let needle_id: String = regex::escape(array_id);
    let body_re_src: String = format!(
        r"(?ms)\(\s*function\s*\(([^)]*)\)\s*\{{(.+?)\}}\s*\(\s*{needle_id}\s*,\s*([-+]?0x[0-9a-fA-F]+|\d+)\s*\)\s*\)\s*;",
    );
    let body_re: Regex = Regex::new(&body_re_src).ok()?;
    let cap: regex::Captures<'_> = body_re.captures(source)?;
    let body: &str = cap.get(2)?.as_str();
    if !looks_like_rotator(body) {
        return None;
    }
    let pivot_value: i64 = parse_int_literal(cap.get(3)?.as_str())?;
    let pivot_index: usize = find_pivot_index(body).unwrap_or(0);
    let whole: regex::Match<'_> = cap.get(0)?;
    Some(RotatorFound {
        pivot_index,
        pivot_value,
        iife_range: whole.start()..whole.end(),
    })
}

fn looks_like_rotator(body: &str) -> bool {
    let has_loop: bool = body.contains("while") && (body.contains("!![]") || body.contains("true"));
    let has_push_shift: bool = body.contains("push") && body.contains("shift");
    let has_parse_int: bool = body.contains("parseInt");
    has_loop && has_push_shift && has_parse_int
}

fn find_pivot_index(body: &str) -> Option<usize> {
    let pivot_re: Regex = Regex::new(r"parseInt\([^)]*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)").ok()?;
    let cap: regex::Captures<'_> = pivot_re.captures(body)?;
    let raw: &str = cap.get(1)?.as_str();
    parse_int_literal(raw).map(|v| usize::try_from(v).unwrap_or(0))
}

fn parse_int_literal(raw: &str) -> Option<i64> {
    let trimmed: &str = raw.trim();
    let Some(stripped): Option<&str> = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("-0x"))
    else {
        return trimmed.parse::<i64>().ok();
    };
    let sign: i64 = if trimmed.starts_with('-') { -1 } else { 1 };
    let v: i64 = i64::from_str_radix(stripped, 16).ok()?;
    Some(sign * v)
}

fn parse_string_literals(body: &str) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut iter: std::str::Chars<'_> = body.chars();
    while let Some(c) = iter.next() {
        match c {
            '\'' | '"' => {
                let quote: char = c;
                let mut buf: String = String::new();
                while let Some(ch) = iter.next() {
                    if ch == '\\' {
                        if let Some(nx) = iter.next() {
                            match nx {
                                'n' => buf.push('\n'),
                                't' => buf.push('\t'),
                                'r' => buf.push('\r'),
                                '\\' => buf.push('\\'),
                                '\'' => buf.push('\''),
                                '"' => buf.push('"'),
                                '0' => buf.push('\0'),
                                'x' => {
                                    let hi: char = iter.next()?;
                                    let lo: char = iter.next()?;
                                    let v: u8 =
                                        u8::from_str_radix(&format!("{hi}{lo}"), 16).ok()?;
                                    buf.push(v as char);
                                }
                                other => buf.push(other),
                            }
                        }
                    } else if ch == quote {
                        out.push(buf);
                        break;
                    } else {
                        buf.push(ch);
                    }
                }
            }
            ',' | ' ' | '\t' | '\r' | '\n' => {}
            _ => return None,
        }
    }
    Some(out)
}

pub(super) fn rebuild_source(
    source: &str,
    found: &StringArrayFound,
    rotator: &RotatorFound,
    rotated: &(Vec<String>, u32),
) -> String {
    let mut out: String = String::with_capacity(source.len());

    let (first, second): (&std::ops::Range<usize>, &std::ops::Range<usize>) =
        if found.decl_range.start < rotator.iife_range.start {
            (&found.decl_range, &rotator.iife_range)
        } else {
            (&rotator.iife_range, &found.decl_range)
        };

    out.push_str(&source[..first.start]);
    let first_chunk: String = if std::ptr::eq(first, &raw const found.decl_range) {
        emit_array_decl(&found.array_id, &rotated.0)
    } else {
        String::new()
    };
    out.push_str(&first_chunk);

    out.push_str(&source[first.end..second.start]);
    let second_chunk: String = if std::ptr::eq(second, &raw const found.decl_range) {
        emit_array_decl(&found.array_id, &rotated.0)
    } else {
        String::new()
    };
    out.push_str(&second_chunk);

    out.push_str(&source[second.end..]);
    out
}

fn emit_array_decl(id: &str, literals: &[String]) -> String {
    let mut s: String =
        String::with_capacity(literals.iter().map(|l| l.len() + 4).sum::<usize>() + id.len() + 16);
    s.push_str("var ");
    s.push_str(id);
    s.push_str(" = [");
    for (i, lit) in literals.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push('\'');
        for c in lit.chars() {
            match c {
                '\\' => s.push_str("\\\\"),
                '\'' => s.push_str("\\'"),
                '\n' => s.push_str("\\n"),
                '\t' => s.push_str("\\t"),
                '\r' => s.push_str("\\r"),
                _ => s.push(c),
            }
        }
        s.push('\'');
    }
    s.push_str("];");
    s
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_three_string_literals() {
        let out: Vec<String> = parse_string_literals("'a', 'b', 'c'").expect("parse");
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn finds_declaration_and_id() {
        let src: &str = "var _0xabcd = ['log', 'Hello', 'world'];\nrest of code\n";
        let found: StringArrayFound = find_string_array(src).expect("must find decl");
        assert_eq!(found.array_id, "_0xabcd");
        assert_eq!(found.literals, vec!["log", "Hello", "world"]);
    }

    #[test]
    fn parses_int_literal_hex_and_dec() {
        assert_eq!(parse_int_literal("0x1"), Some(1));
        assert_eq!(parse_int_literal("42"), Some(42));
        assert_eq!(parse_int_literal("-0xff"), Some(-255));
    }
}
