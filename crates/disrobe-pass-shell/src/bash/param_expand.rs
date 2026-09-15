const MAX_GLOB_ANCHORED_TEXT_LEN: usize = 4096;
const MAX_GLOB_ANCHORED_PATTERN_LEN: usize = 256;
const MAX_GLOB_SCAN_TEXT_LEN: usize = 512;
const MAX_GLOB_SCAN_PATTERN_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Anchor {
    None,
    Start,
    End,
}

#[derive(Debug, Clone)]
enum GlobTok {
    Lit(char),
    Any,
    Star,
    Class {
        negate: bool,
        ranges: Vec<(char, char)>,
    },
}

fn pattern_has_meta(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' if i + 1 < chars.len() => i += 2,
            '*' | '?' | '[' => return true,
            _ => i += 1,
        }
    }
    false
}

fn unescape_literal(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out: String = String::with_capacity(chars.len());
    let mut i: usize = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            out.push(chars[i + 1]);
            i += 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn compile_glob(pattern: &str) -> Option<Vec<GlobTok>> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut toks: Vec<GlobTok> = Vec::with_capacity(chars.len());
    let mut i: usize = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' if i + 1 < chars.len() => {
                toks.push(GlobTok::Lit(chars[i + 1]));
                i += 2;
            }
            '\\' => {
                toks.push(GlobTok::Lit('\\'));
                i += 1;
            }
            '*' => {
                toks.push(GlobTok::Star);
                i += 1;
            }
            '?' => {
                toks.push(GlobTok::Any);
                i += 1;
            }
            '[' => {
                let mut j: usize = i + 1;
                let negate: bool = matches!(chars.get(j), Some('!' | '^'));
                if negate {
                    j += 1;
                }
                let class_start: usize = j;
                if chars.get(j) == Some(&']') {
                    j += 1;
                }
                while j < chars.len() && chars[j] != ']' {
                    j += 1;
                }
                if j >= chars.len() {
                    toks.push(GlobTok::Lit('['));
                    i += 1;
                    continue;
                }
                let body: &[char] = &chars[class_start..j];
                let Some(ranges) = parse_class_ranges(body) else {
                    toks.push(GlobTok::Lit('['));
                    i += 1;
                    continue;
                };
                toks.push(GlobTok::Class { negate, ranges });
                i = j + 1;
            }
            c => {
                toks.push(GlobTok::Lit(c));
                i += 1;
            }
        }
    }
    Some(toks)
}

fn parse_class_ranges(body: &[char]) -> Option<Vec<(char, char)>> {
    if body.is_empty() {
        return None;
    }
    let mut ranges: Vec<(char, char)> = Vec::with_capacity(body.len());
    let mut i: usize = 0;
    while i < body.len() {
        if i + 2 < body.len() && body[i + 1] == '-' && body[i] <= body[i + 2] {
            ranges.push((body[i], body[i + 2]));
            i += 3;
        } else {
            ranges.push((body[i], body[i]));
            i += 1;
        }
    }
    Some(ranges)
}

fn class_hit(ranges: &[(char, char)], negate: bool, c: char) -> bool {
    let hit: bool = ranges
        .iter()
        .any(|(lo, hi): &(char, char)| *lo <= c && c <= *hi);
    hit != negate
}

fn tok_matches(tok: &GlobTok, c: char) -> bool {
    match tok {
        GlobTok::Lit(l) => *l == c,
        GlobTok::Any => true,
        GlobTok::Star => false,
        GlobTok::Class { negate, ranges } => class_hit(ranges, *negate, c),
    }
}

fn forward_match_row(toks: &[GlobTok], text: &[char]) -> Vec<bool> {
    let n: usize = toks.len();
    let m: usize = text.len();
    let mut dp: Vec<Vec<bool>> = vec![vec![false; m + 1]; n + 1];
    dp[0][0] = true;
    for i in 1..=n {
        if matches!(toks[i - 1], GlobTok::Star) {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = match &toks[i - 1] {
                GlobTok::Star => dp[i - 1][j] || dp[i][j - 1],
                tok => dp[i - 1][j - 1] && tok_matches(tok, text[j - 1]),
            };
        }
    }
    dp[n].clone()
}

fn suffix_match_row(toks: &[GlobTok], text: &[char]) -> Vec<bool> {
    let m: usize = text.len();
    let rev_text: Vec<char> = text.iter().rev().copied().collect();
    let rev_toks: Vec<GlobTok> = toks.iter().rev().cloned().collect();
    let fwd: Vec<bool> = forward_match_row(&rev_toks, &rev_text);
    let mut result: Vec<bool> = vec![false; m + 1];
    for k in 0..=m {
        result[m - k] = fwd[k];
    }
    result
}

pub(crate) fn trim_prefix(value: &str, pattern: &str, longest: bool) -> Option<String> {
    if pattern.is_empty() {
        return Some(value.to_owned());
    }
    if !pattern_has_meta(pattern) {
        let literal: String = unescape_literal(pattern);
        return Some(match value.strip_prefix(literal.as_str()) {
            Some(rest) => rest.to_owned(),
            None => value.to_owned(),
        });
    }
    let toks: Vec<GlobTok> = compile_glob(pattern)?;
    let chars: Vec<char> = value.chars().collect();
    if chars.len() > MAX_GLOB_ANCHORED_TEXT_LEN || toks.len() > MAX_GLOB_ANCHORED_PATTERN_LEN {
        return None;
    }
    let row: Vec<bool> = forward_match_row(&toks, &chars);
    let candidates = (0..=chars.len()).filter(|j: &usize| row[*j]);
    let chosen: Option<usize> = if longest {
        candidates.max()
    } else {
        candidates.min()
    };
    Some(match chosen {
        Some(j) => chars[j..].iter().collect(),
        None => value.to_owned(),
    })
}

pub(crate) fn trim_suffix(value: &str, pattern: &str, longest: bool) -> Option<String> {
    if pattern.is_empty() {
        return Some(value.to_owned());
    }
    if !pattern_has_meta(pattern) {
        let literal: String = unescape_literal(pattern);
        return Some(match value.strip_suffix(literal.as_str()) {
            Some(rest) => rest.to_owned(),
            None => value.to_owned(),
        });
    }
    let toks: Vec<GlobTok> = compile_glob(pattern)?;
    let chars: Vec<char> = value.chars().collect();
    if chars.len() > MAX_GLOB_ANCHORED_TEXT_LEN || toks.len() > MAX_GLOB_ANCHORED_PATTERN_LEN {
        return None;
    }
    let row: Vec<bool> = suffix_match_row(&toks, &chars);
    let candidates = (0..=chars.len()).filter(|j: &usize| row[*j]);
    let chosen: Option<usize> = if longest {
        candidates.min()
    } else {
        candidates.max()
    };
    Some(match chosen {
        Some(j) => chars[..j].iter().collect(),
        None => value.to_owned(),
    })
}

fn substitute_literal(
    value: &str,
    pattern: &str,
    replacement: &str,
    all: bool,
    anchor: Anchor,
) -> String {
    match anchor {
        Anchor::Start => match value.strip_prefix(pattern) {
            Some(rest) => format!("{replacement}{rest}"),
            None => value.to_owned(),
        },
        Anchor::End => match value.strip_suffix(pattern) {
            Some(rest) => format!("{rest}{replacement}"),
            None => value.to_owned(),
        },
        Anchor::None => {
            if all {
                value.replace(pattern, replacement)
            } else {
                value.replacen(pattern, replacement, 1)
            }
        }
    }
}

fn substitute_anchored_glob(
    chars: &[char],
    toks: &[GlobTok],
    replacement: &str,
    anchor: Anchor,
) -> String {
    match anchor {
        Anchor::Start => {
            let row: Vec<bool> = forward_match_row(toks, chars);
            let best: Option<usize> = (0..=chars.len()).rev().find(|j: &usize| row[*j]);
            match best {
                Some(j) if j > 0 => {
                    let rest: String = chars[j..].iter().collect();
                    format!("{replacement}{rest}")
                }
                _ => chars.iter().collect(),
            }
        }
        Anchor::End => {
            let row: Vec<bool> = suffix_match_row(toks, chars);
            let best: Option<usize> = (0..=chars.len()).find(|j: &usize| row[*j]);
            match best {
                Some(j) if j < chars.len() => {
                    let head: String = chars[..j].iter().collect();
                    format!("{head}{replacement}")
                }
                _ => chars.iter().collect(),
            }
        }
        Anchor::None => chars.iter().collect(),
    }
}

fn substitute_scan_glob(chars: &[char], toks: &[GlobTok], replacement: &str, all: bool) -> String {
    let m: usize = chars.len();
    let mut out: String = String::with_capacity(m + replacement.len());
    let mut pos: usize = 0;
    while pos <= m {
        let remaining: &[char] = &chars[pos..];
        let row: Vec<bool> = forward_match_row(toks, remaining);
        let best: Option<usize> = (0..=remaining.len()).rev().find(|j: &usize| row[*j]);
        match best {
            Some(len) if len > 0 => {
                out.push_str(replacement);
                pos += len;
                if !all {
                    out.extend(&chars[pos..]);
                    return out;
                }
            }
            _ => {
                if pos < m {
                    out.push(chars[pos]);
                }
                pos += 1;
            }
        }
    }
    out
}

pub(crate) fn substitute(
    value: &str,
    pattern: &str,
    replacement: &str,
    all: bool,
    anchor: Anchor,
) -> Option<String> {
    if pattern.is_empty() {
        return None;
    }
    if !pattern_has_meta(pattern) {
        let literal: String = unescape_literal(pattern);
        if literal.is_empty() {
            return None;
        }
        return Some(substitute_literal(
            value,
            &literal,
            replacement,
            all,
            anchor,
        ));
    }
    let toks: Vec<GlobTok> = compile_glob(pattern)?;
    let chars: Vec<char> = value.chars().collect();
    match anchor {
        Anchor::Start | Anchor::End => {
            if chars.len() > MAX_GLOB_ANCHORED_TEXT_LEN
                || toks.len() > MAX_GLOB_ANCHORED_PATTERN_LEN
            {
                return None;
            }
            Some(substitute_anchored_glob(&chars, &toks, replacement, anchor))
        }
        Anchor::None => {
            if chars.len() > MAX_GLOB_SCAN_TEXT_LEN || toks.len() > MAX_GLOB_SCAN_PATTERN_LEN {
                return None;
            }
            Some(substitute_scan_glob(&chars, &toks, replacement, all))
        }
    }
}

pub(crate) fn substring(value: &str, offset: i64, length: Option<i64>) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    let total: i64 = i64::try_from(chars.len()).ok()?;
    let raw_start: i64 = if offset < 0 {
        total.saturating_add(offset)
    } else {
        offset
    };
    if raw_start < 0 {
        return Some(String::new());
    }
    let start: i64 = raw_start.min(total);
    let end: i64 = match length {
        None => total,
        Some(l) if l >= 0 => start.saturating_add(l).min(total),
        Some(l) => {
            let raw_end: i64 = total.saturating_add(l);
            if raw_end < start {
                return None;
            }
            raw_end
        }
    };
    if start >= end {
        return Some(String::new());
    }
    Some(chars[start as usize..end as usize].iter().collect())
}

pub(crate) fn parse_substring_spec(spec: &str) -> Option<(i64, Option<i64>)> {
    let trimmed: &str = spec.trim();
    let (off_part, len_part): (&str, Option<&str>) = match trimmed.split_once(':') {
        Some((a, b)) => (a.trim(), Some(b.trim())),
        None => (trimmed, None),
    };
    if off_part.is_empty() {
        return None;
    }
    let offset: i64 = off_part.parse().ok()?;
    let length: Option<i64> = match len_part {
        None => None,
        Some("") => return None,
        Some(l) => Some(l.parse().ok()?),
    };
    Some((offset, length))
}

pub(crate) fn case_convert(value: &str, upper: bool, all: bool) -> String {
    if all {
        return if upper {
            value.to_uppercase()
        } else {
            value.to_lowercase()
        };
    }
    let mut chars: std::str::Chars<'_> = value.chars();
    match chars.next() {
        Some(first) => {
            let converted: String = if upper {
                first.to_uppercase().collect()
            } else {
                first.to_lowercase().collect()
            };
            format!("{converted}{}", chars.as_str())
        }
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_prefix_literal_removes_once() {
        assert_eq!(
            trim_prefix("abcabcabc", "abc", false).as_deref(),
            Some("abcabc")
        );
        assert_eq!(
            trim_prefix("abcabcabc", "abc", true).as_deref(),
            Some("abcabc")
        );
    }

    #[test]
    fn trim_prefix_glob_shortest_vs_longest() {
        assert_eq!(
            trim_prefix("foo123bar", "*[0-9]", false).as_deref(),
            Some("23bar")
        );
        assert_eq!(
            trim_prefix("foo123bar", "*[0-9]", true).as_deref(),
            Some("bar")
        );
    }

    #[test]
    fn trim_prefix_star_only() {
        assert_eq!(trim_prefix("abc", "*", false).as_deref(), Some("abc"));
        assert_eq!(trim_prefix("abc", "*", true).as_deref(), Some(""));
    }

    #[test]
    fn trim_suffix_glob_shortest_vs_longest() {
        assert_eq!(
            trim_suffix("foo123bar", "[0-9]*", false).as_deref(),
            Some("foo12")
        );
        assert_eq!(
            trim_suffix("foo123bar", "[0-9]*", true).as_deref(),
            Some("foo")
        );
    }

    #[test]
    fn trim_no_match_leaves_value_unchanged() {
        assert_eq!(trim_prefix("abc", "zzz", false).as_deref(), Some("abc"));
        assert_eq!(trim_suffix("abc", "zzz", true).as_deref(), Some("abc"));
    }

    #[test]
    fn substitute_literal_first_and_all() {
        assert_eq!(
            substitute("xxaxxaxx", "xx", "", false, Anchor::None).as_deref(),
            Some("axxaxx")
        );
        assert_eq!(
            substitute("xxaxxaxx", "xx", "", true, Anchor::None).as_deref(),
            Some("aa")
        );
    }

    #[test]
    fn substitute_glob_leftmost_longest() {
        assert_eq!(
            substitute("abcabcabc", "b*c", "X", false, Anchor::None).as_deref(),
            Some("aX")
        );
        assert_eq!(
            substitute("abcabcabc", "b*c", "X", true, Anchor::None).as_deref(),
            Some("aX")
        );
    }

    #[test]
    fn substitute_anchored_start_and_end() {
        assert_eq!(
            substitute("abcabcabc", "a*b", "X", false, Anchor::Start).as_deref(),
            Some("Xc")
        );
        assert_eq!(
            substitute("abcabcabc", "b*c", "X", false, Anchor::End).as_deref(),
            Some("aX")
        );
        assert_eq!(
            substitute("abcabcabc", "a*z", "X", false, Anchor::Start).as_deref(),
            Some("abcabcabc")
        );
    }

    #[test]
    fn substitute_rejects_empty_pattern() {
        assert!(substitute("abc", "", "X", false, Anchor::None).is_none());
    }

    #[test]
    fn substring_matches_bash_offsets() {
        assert_eq!(substring("abcdefgh", 2, Some(-2)).as_deref(), Some("cdef"));
        assert_eq!(
            substring("abcdefgh", 0, Some(-1)).as_deref(),
            Some("abcdefg")
        );
        assert_eq!(substring("abcdefgh", -8, None).as_deref(), Some("abcdefgh"));
        assert_eq!(substring("abcdefgh", -9, None).as_deref(), Some(""));
        assert_eq!(substring("abcdefgh", 9, None).as_deref(), Some(""));
        assert_eq!(substring("abcdefgh", -8, Some(3)).as_deref(), Some("abc"));
        assert_eq!(substring("abcdefgh", -9, Some(3)).as_deref(), Some(""));
    }

    #[test]
    fn substring_negative_length_below_start_is_unresolved() {
        assert!(substring("abcdefgh", 2, Some(-10)).is_none());
    }

    #[test]
    fn parse_substring_spec_offset_only_and_with_length() {
        assert_eq!(parse_substring_spec(" 2 "), Some((2, None)));
        assert_eq!(parse_substring_spec("2:3"), Some((2, Some(3))));
        assert_eq!(parse_substring_spec(" -3 : 1 "), Some((-3, Some(1))));
        assert_eq!(parse_substring_spec("not-a-number"), None);
    }

    #[test]
    fn case_convert_matches_bash_caret_and_comma() {
        assert_eq!(case_convert("Hello World", true, true), "HELLO WORLD");
        assert_eq!(case_convert("Hello World", false, true), "hello world");
        assert_eq!(case_convert("abcdefabc", true, false), "Abcdefabc");
        assert_eq!(case_convert("", true, false), "");
    }
}
