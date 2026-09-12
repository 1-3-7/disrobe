use std::sync::LazyLock;

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfOutcome {
    Taken(String),
    NotTaken(Option<String>),
    Unknown,
}

static IF_HEAD: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?is)^\s*if\s+(?P<rest>.+)$"));

const OPERATORS: &[(&str, Cmp)] = &[
    ("==", Cmp::Eq),
    (" equ ", Cmp::NumEq),
    (" neq ", Cmp::NumNe),
    (" lss ", Cmp::NumLt),
    (" leq ", Cmp::NumLe),
    (" gtr ", Cmp::NumGt),
    (" geq ", Cmp::NumGe),
];

#[derive(Debug, Clone, Copy)]
enum Cmp {
    Eq,
    NumEq,
    NumNe,
    NumLt,
    NumLe,
    NumGt,
    NumGe,
}

#[must_use]
pub fn eval_if(line: &str) -> IfOutcome {
    let Some(cap): Option<regex::Captures<'_>> = IF_HEAD.captures(line) else {
        return IfOutcome::Unknown;
    };
    let Some(rest_m): Option<regex::Match<'_>> = cap.name("rest") else {
        return IfOutcome::Unknown;
    };
    let mut rest: String = rest_m.as_str().trim().to_owned();

    let case_insensitive: bool = strip_flag(&mut rest, "/i");
    let mut negate: bool = false;
    while strip_leading_keyword(&mut rest, "not") {
        negate = !negate;
    }

    let lower: String = rest.to_ascii_lowercase();
    if lower.starts_with("errorlevel ")
        || lower.starts_with("exist ")
        || lower.starts_with("cmdextversion ")
    {
        return IfOutcome::Unknown;
    }

    if leading_keyword(&rest, "defined").is_some() {
        return IfOutcome::Unknown;
    }
    let Some((left, cmp, op_end)): Option<(&str, Cmp, usize)> = find_operator(&rest) else {
        return IfOutcome::Unknown;
    };
    let Some((right, body_start)): Option<(String, usize)> = read_operand(&rest[op_end..]) else {
        return IfOutcome::Unknown;
    };
    let left_v: String = unquote(left.trim());
    let right_v: String = unquote(right.trim());
    if contains_unexpanded(&left_v) || contains_unexpanded(&right_v) {
        return IfOutcome::Unknown;
    }
    let Some(result): Option<bool> = compare(&left_v, &right_v, cmp, case_insensitive) else {
        return IfOutcome::Unknown;
    };
    let body_abs: usize = op_end + body_start;
    decide(result, negate, &rest, body_abs)
}

fn decide(condition: bool, negate: bool, rest: &str, body_start: usize) -> IfOutcome {
    let taken: bool = condition ^ negate;
    let body_region: &str = rest.get(body_start..).unwrap_or("").trim_start();
    let (then_body, else_body): (String, Option<String>) = split_else(body_region);
    if taken {
        IfOutcome::Taken(then_body)
    } else {
        IfOutcome::NotTaken(else_body)
    }
}

fn split_else(body: &str) -> (String, Option<String>) {
    let trimmed: &str = body.trim();
    let (then_part, rest): (&str, &str) = if let Some(stripped) = trimmed.strip_prefix('(') {
        match find_matching_paren(stripped) {
            Some(at) => (&stripped[..at], stripped[at + 1..].trim_start()),
            None => return (unwrap_block(trimmed), None),
        }
    } else {
        (trimmed, "")
    };
    let then_clean: String = then_part.trim().to_owned();
    let lower_rest: String = rest.to_ascii_lowercase();
    if let Some(after_else) = lower_rest.strip_prefix("else") {
        let cut: usize = rest.len() - after_else.len();
        let else_raw: &str = rest[cut..].trim_start();
        let else_body: String = if let Some(stripped) = else_raw.strip_prefix('(') {
            match find_matching_paren(stripped) {
                Some(at) => stripped[..at].trim().to_owned(),
                None => stripped.trim().to_owned(),
            }
        } else {
            else_raw.trim().to_owned()
        };
        (then_clean, Some(else_body))
    } else {
        (then_clean, None)
    }
}

fn unwrap_block(s: &str) -> String {
    let t: &str = s.trim();
    if let Some(inner) = t.strip_prefix('(').and_then(|x: &str| x.strip_suffix(')')) {
        inner.trim().to_owned()
    } else {
        t.to_owned()
    }
}

fn find_matching_paren(s: &str) -> Option<usize> {
    let chars: Vec<char> = s.chars().collect();
    let mut depth: usize = 0;
    let mut in_quote: bool = false;
    let mut byte_idx: usize = 0;
    for c in chars {
        if c == '"' {
            in_quote = !in_quote;
        }
        if !in_quote {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                if depth == 0 {
                    return Some(byte_idx);
                }
                depth -= 1;
            }
        }
        byte_idx += c.len_utf8();
    }
    None
}

fn find_operator(rest: &str) -> Option<(&str, Cmp, usize)> {
    let lower: String = rest.to_ascii_lowercase();
    let mut best: Option<(usize, usize, Cmp)> = None;
    for (token, cmp) in OPERATORS {
        if let Some(at) = lower.find(token) {
            let better: bool = best.is_none_or(|(b, _, _): (usize, usize, Cmp)| at < b);
            if better {
                best = Some((at, token.len(), *cmp));
            }
        }
    }
    let (at, len, cmp): (usize, usize, Cmp) = best?;
    Some((&rest[..at], cmp, at + len))
}

fn read_operand(s: &str) -> Option<(String, usize)> {
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    if bytes[i] == b'"' {
        let start: usize = i;
        i += 1;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        i += 1;
        return Some((s[start..i].to_owned(), i));
    }
    let start: usize = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'(' {
        i += 1;
    }
    Some((s[start..i].to_owned(), i))
}

fn compare(left: &str, right: &str, cmp: Cmp, case_insensitive: bool) -> Option<bool> {
    match cmp {
        Cmp::Eq => {
            if case_insensitive {
                Some(left.eq_ignore_ascii_case(right))
            } else {
                Some(left == right)
            }
        }
        Cmp::NumEq | Cmp::NumNe | Cmp::NumLt | Cmp::NumLe | Cmp::NumGt | Cmp::NumGe => {
            let lhs: i64 = left.parse::<i64>().ok()?;
            let rhs: i64 = right.parse::<i64>().ok()?;
            let result: bool = match cmp {
                Cmp::NumEq => lhs == rhs,
                Cmp::NumNe => lhs != rhs,
                Cmp::NumLt => lhs < rhs,
                Cmp::NumLe => lhs <= rhs,
                Cmp::NumGt => lhs > rhs,
                Cmp::NumGe => lhs >= rhs,
                Cmp::Eq => unreachable!(),
            };
            Some(result)
        }
    }
}

fn strip_flag(rest: &mut String, flag: &str) -> bool {
    let lower: String = rest.to_ascii_lowercase();
    let target: String = format!("{flag} ");
    if lower.starts_with(&target) {
        *rest = rest[target.len()..].trim_start().to_owned();
        true
    } else {
        false
    }
}

fn strip_leading_keyword(rest: &mut String, keyword: &str) -> bool {
    let lower: String = rest.to_ascii_lowercase();
    let kw: String = format!("{keyword} ");
    if lower.starts_with(&kw) {
        *rest = rest[kw.len()..].trim_start().to_owned();
        true
    } else {
        false
    }
}

fn leading_keyword<'a>(rest: &'a str, keyword: &str) -> Option<&'a str> {
    let lower: String = rest.to_ascii_lowercase();
    let kw: String = format!("{keyword} ");
    if lower.starts_with(&kw) {
        Some(&rest[kw.len()..])
    } else {
        None
    }
}

fn unquote(s: &str) -> String {
    let t: &str = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].to_owned()
    } else {
        t.to_owned()
    }
}

fn contains_unexpanded(s: &str) -> bool {
    s.contains('%') || s.contains('!')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_strings_take_then() {
        let r: IfOutcome = eval_if("if \"a\"==\"a\" echo yes");
        assert_eq!(r, IfOutcome::Taken("echo yes".to_owned()));
    }

    #[test]
    fn unequal_strings_not_taken_no_else() {
        let r: IfOutcome = eval_if("if \"a\"==\"b\" echo yes");
        assert_eq!(r, IfOutcome::NotTaken(None));
    }

    #[test]
    fn unequal_strings_with_else() {
        let r: IfOutcome = eval_if("if \"a\"==\"b\" (echo yes) else (echo no)");
        assert_eq!(r, IfOutcome::NotTaken(Some("echo no".to_owned())));
    }

    #[test]
    fn equal_with_else_takes_then_block() {
        let r: IfOutcome = eval_if("if \"x\"==\"x\" (echo hit) else (echo miss)");
        assert_eq!(r, IfOutcome::Taken("echo hit".to_owned()));
    }

    #[test]
    fn case_insensitive_flag() {
        let r: IfOutcome = eval_if("if /i \"ABC\"==\"abc\" echo match");
        assert_eq!(r, IfOutcome::Taken("echo match".to_owned()));
    }

    #[test]
    fn case_sensitive_default_differs() {
        let r: IfOutcome = eval_if("if \"ABC\"==\"abc\" echo match");
        assert_eq!(r, IfOutcome::NotTaken(None));
    }

    #[test]
    fn numeric_geq() {
        assert_eq!(
            eval_if("if 5 geq 3 echo big"),
            IfOutcome::Taken("echo big".to_owned())
        );
        assert_eq!(eval_if("if 2 geq 3 echo big"), IfOutcome::NotTaken(None));
    }

    #[test]
    fn not_inverts() {
        assert_eq!(
            eval_if("if not \"a\"==\"b\" echo diff"),
            IfOutcome::Taken("echo diff".to_owned())
        );
    }

    #[test]
    fn errorlevel_is_unknown() {
        assert_eq!(eval_if("if errorlevel 1 echo failed"), IfOutcome::Unknown);
    }

    #[test]
    fn exist_is_unknown() {
        assert_eq!(eval_if("if exist c:\\x.txt echo here"), IfOutcome::Unknown);
    }

    #[test]
    fn unexpanded_var_is_unknown() {
        assert_eq!(eval_if("if \"%X%\"==\"1\" echo one"), IfOutcome::Unknown);
    }

    #[test]
    fn multiline_block_then_branch_extracted() {
        let line: &str = "if 1 equ 1 (\n  powershell -enc AAAA\n) else (\n  echo decoy\n)";
        assert_eq!(
            eval_if(line),
            IfOutcome::Taken("powershell -enc AAAA".to_owned())
        );
    }

    #[test]
    fn multiline_block_else_branch_extracted() {
        let line: &str = "if 1 equ 2 (\n  echo then\n) else (\n  echo otherwise\n)";
        assert_eq!(
            eval_if(line),
            IfOutcome::NotTaken(Some("echo otherwise".to_owned()))
        );
    }
}
