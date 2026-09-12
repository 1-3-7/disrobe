use std::collections::BTreeMap;

pub const MAX_EXPANSION_OUTPUT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ExpandStats {
    pub var_refs: usize,
    pub delayed_refs: usize,
    pub substrings: usize,
    pub substitutions: usize,
    pub tilde_params: usize,
}

impl ExpandStats {
    const fn zero() -> Self {
        Self {
            var_refs: 0,
            delayed_refs: 0,
            substrings: 0,
            substitutions: 0,
            tilde_params: 0,
        }
    }

    fn merge(&mut self, other: Self) {
        self.var_refs += other.var_refs;
        self.delayed_refs += other.delayed_refs;
        self.substrings += other.substrings;
        self.substitutions += other.substitutions;
        self.tilde_params += other.tilde_params;
    }

    #[must_use]
    pub const fn total(&self) -> usize {
        self.var_refs + self.delayed_refs + self.substrings + self.substitutions + self.tilde_params
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sigil {
    Percent,
    Bang,
}

#[must_use]
pub fn expand_line(
    line: &str,
    env: &BTreeMap<String, String>,
    args: &[String],
    delayed: bool,
) -> (String, ExpandStats) {
    let mut stats: ExpandStats = ExpandStats::zero();
    let after_percent: String = expand_sigil(line, env, args, Sigil::Percent, &mut stats);
    if delayed {
        let after_bang: String = expand_sigil(&after_percent, env, args, Sigil::Bang, &mut stats);
        (after_bang, stats)
    } else {
        (after_percent, stats)
    }
}

fn expand_sigil(
    input: &str,
    env: &BTreeMap<String, String>,
    args: &[String],
    sigil: Sigil,
    stats: &mut ExpandStats,
) -> String {
    let delim: char = match sigil {
        Sigil::Percent => '%',
        Sigil::Bang => '!',
    };
    let mut out: String = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        if out.len() > MAX_EXPANSION_OUTPUT {
            out.extend(chars[i..].iter().copied());
            break;
        }
        let c: char = chars[i];
        if sigil == Sigil::Percent && c == '%' {
            if let Some((tilde, consumed)) = try_tilde_param(&chars[i..], args, stats) {
                out.push_str(&tilde);
                i += consumed;
                continue;
            }
            if let Some((digit, consumed)) = try_positional(&chars[i..], args) {
                out.push_str(&digit);
                i += consumed;
                continue;
            }
        }
        if c == delim
            && let Some((value, consumed)) = try_variable(&chars[i..], delim, env, sigil, stats)
        {
            out.push_str(&value);
            i += consumed;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn try_variable(
    chars: &[char],
    delim: char,
    env: &BTreeMap<String, String>,
    sigil: Sigil,
    stats: &mut ExpandStats,
) -> Option<(String, usize)> {
    let close: usize = find_close(chars, delim)?;
    let inner: String = chars[1..close].iter().collect();
    let consumed: usize = close + 1;
    if inner.is_empty() || inner.contains(delim) {
        return None;
    }

    if let Some((name, spec)) = inner.split_once(":~") {
        let value: &String = env.get(&name.to_ascii_uppercase())?;
        let sliced: String = apply_substring(value, spec)?;
        bump_sigil(stats, sigil);
        stats.substrings += 1;
        return Some((sliced, consumed));
    }
    if let Some((name, spec)) = inner.split_once(':') {
        let value: &String = env.get(&name.to_ascii_uppercase())?;
        let replaced: String = apply_substitution(value, spec)?;
        bump_sigil(stats, sigil);
        stats.substitutions += 1;
        return Some((replaced, consumed));
    }
    let value: &String = env.get(&inner.to_ascii_uppercase())?;
    bump_sigil(stats, sigil);
    Some((value.clone(), consumed))
}

const fn bump_sigil(stats: &mut ExpandStats, sigil: Sigil) {
    match sigil {
        Sigil::Percent => stats.var_refs += 1,
        Sigil::Bang => stats.delayed_refs += 1,
    }
}

fn find_close(chars: &[char], delim: char) -> Option<usize> {
    let mut i: usize = 1;
    while i < chars.len() {
        if chars[i] == delim {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn try_positional(chars: &[char], args: &[String]) -> Option<(String, usize)> {
    if chars.len() < 2 || chars[0] != '%' {
        return None;
    }
    let digit: char = chars[1];
    if !digit.is_ascii_digit() {
        return None;
    }
    let idx: usize = digit as usize - '0' as usize;
    let value: String = args.get(idx).cloned().unwrap_or_default();
    Some((value, 2))
}

fn try_tilde_param(
    chars: &[char],
    args: &[String],
    stats: &mut ExpandStats,
) -> Option<(String, usize)> {
    if chars.len() < 3 || chars[0] != '%' || chars[1] != '~' {
        return None;
    }
    let mut i: usize = 2;
    let mut modifiers: String = String::new();
    while i < chars.len() && is_modifier_char(chars[i]) {
        modifiers.push(chars[i].to_ascii_lowercase());
        i += 1;
    }
    let digit: char = *chars.get(i)?;
    if !digit.is_ascii_digit() {
        return None;
    }
    i += 1;
    let idx: usize = digit as usize - '0' as usize;
    let value: String = args.get(idx).cloned().unwrap_or_default();
    let unquoted: String = value.trim_matches('"').to_owned();
    let rendered: String = apply_param_modifiers(&unquoted, &modifiers);
    stats.tilde_params += 1;
    Some((rendered, i))
}

const fn is_modifier_char(c: char) -> bool {
    matches!(
        c,
        'd' | 'p'
            | 'n'
            | 'x'
            | 's'
            | 'a'
            | 'f'
            | 't'
            | 'z'
            | 'D'
            | 'P'
            | 'N'
            | 'X'
            | 'S'
            | 'A'
            | 'F'
            | 'T'
            | 'Z'
    )
}

fn apply_param_modifiers(value: &str, modifiers: &str) -> String {
    if modifiers.is_empty() {
        return value.to_owned();
    }
    if modifiers.contains('f') {
        return value.to_owned();
    }
    let normalized: String = value.replace('/', "\\");
    let (dir, file): (&str, &str) = match normalized.rfind('\\') {
        Some(at) => (&normalized[..=at], &normalized[at + 1..]),
        None => ("", normalized.as_str()),
    };
    let (stem, ext): (&str, &str) = match file.rfind('.') {
        Some(at) if at > 0 => (&file[..at], &file[at..]),
        _ => (file, ""),
    };
    let drive: &str = if normalized.len() >= 2 && &normalized[1..2] == ":" {
        &normalized[..2]
    } else {
        ""
    };
    let path_no_drive: &str = if drive.is_empty() {
        dir
    } else {
        dir.get(2..).unwrap_or("")
    };
    let mut out: String = String::new();
    for m in modifiers.chars() {
        match m {
            'd' => out.push_str(drive),
            'p' => out.push_str(path_no_drive),
            'n' => out.push_str(stem),
            'x' => out.push_str(ext),
            _ => {}
        }
    }
    if out.is_empty() {
        value.to_owned()
    } else {
        out
    }
}

fn apply_substring(value: &str, spec: &str) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    let len_total: i64 = chars.len() as i64;
    let (start_part, len_part): (&str, Option<&str>) = match spec.split_once(',') {
        Some((s, l)) => (s, Some(l)),
        None => (spec, None),
    };
    let start_signed: i64 = start_part.trim().parse::<i64>().ok()?;
    let start: i64 = if start_signed < 0 {
        clamp_relative_index(len_total, start_signed)
    } else {
        start_signed.min(len_total)
    };
    let end: i64 = match len_part {
        None => len_total,
        Some(l) => {
            let l_val: i64 = l.trim().parse::<i64>().ok()?;
            if l_val < 0 {
                clamp_relative_index(len_total, l_val).max(start)
            } else {
                start.checked_add(l_val).unwrap_or(i64::MAX).min(len_total)
            }
        }
    };
    if start > end || start < 0 {
        return Some(String::new());
    }
    Some(chars[start as usize..end as usize].iter().collect())
}

fn clamp_relative_index(base: i64, offset: i64) -> i64 {
    base.checked_add(offset)
        .unwrap_or(if offset < 0 { i64::MIN } else { i64::MAX })
        .clamp(0, base)
}

fn apply_substitution(value: &str, spec: &str) -> Option<String> {
    let (find_raw, replace): (&str, &str) = spec.split_once('=')?;
    if find_raw.is_empty() {
        return None;
    }
    if let Some(stripped) = find_raw.strip_prefix('*') {
        if stripped.is_empty() {
            return None;
        }
        let lower_value: String = value.to_ascii_lowercase();
        let lower_find: String = stripped.to_ascii_lowercase();
        if let Some(at) = lower_value.find(&lower_find) {
            let tail: &str = &value[at + stripped.len()..];
            return Some(format!("{replace}{tail}"));
        }
        return Some(value.to_owned());
    }
    Some(replace_case_insensitive(value, find_raw, replace))
}

fn replace_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    let lower_hay: String = haystack.to_ascii_lowercase();
    let lower_needle: String = needle.to_ascii_lowercase();
    let mut out: String = String::with_capacity(haystack.len());
    let mut last: usize = 0;
    let mut search_from: usize = 0;
    while let Some(rel) = lower_hay[search_from..].find(&lower_needle) {
        let at: usize = search_from + rel;
        out.push_str(&haystack[last..at]);
        out.push_str(replacement);
        last = at + needle.len();
        search_from = last;
    }
    out.push_str(&haystack[last..]);
    out
}

#[must_use]
pub fn expand_repeated(
    line: &str,
    env: &BTreeMap<String, String>,
    args: &[String],
    delayed: bool,
    max_rounds: usize,
) -> (String, ExpandStats) {
    let mut current: String = line.to_owned();
    let mut total: ExpandStats = ExpandStats::zero();
    for _ in 0..max_rounds {
        let (next, stats): (String, ExpandStats) = expand_line(&current, env, args, delayed);
        total.merge(stats);
        if next == current {
            break;
        }
        current = next;
    }
    (current, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v): &(&str, &str)| (k.to_ascii_uppercase(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn expansion_output_is_ceiling_bounded() {
        let big: String = "a".repeat(MAX_EXPANSION_OUTPUT / 2);
        let env: BTreeMap<String, String> = env_of(&[("A", big.as_str())]);
        let (out, _stats): (String, ExpandStats) = expand_line("%A%%A%%A%%A%", &env, &[], false);
        assert!(out.len() <= MAX_EXPANSION_OUTPUT + big.len() + 16);
    }

    #[test]
    fn expands_plain_percent() {
        let env: BTreeMap<String, String> = env_of(&[("CMD", "whoami")]);
        let (out, stats): (String, ExpandStats) = expand_line("%CMD%", &env, &[], false);
        assert_eq!(out, "whoami");
        assert_eq!(stats.var_refs, 1);
    }

    #[test]
    fn expands_delayed_bang() {
        let env: BTreeMap<String, String> = env_of(&[("X", "hi")]);
        let (out, stats): (String, ExpandStats) = expand_line("!X!", &env, &[], true);
        assert_eq!(out, "hi");
        assert_eq!(stats.delayed_refs, 1);
    }

    #[test]
    fn bang_not_expanded_when_delayed_off() {
        let env: BTreeMap<String, String> = env_of(&[("X", "hi")]);
        let (out, _): (String, ExpandStats) = expand_line("!X!", &env, &[], false);
        assert_eq!(out, "!X!");
    }

    #[test]
    fn substring_positive() {
        let env: BTreeMap<String, String> = env_of(&[("V", "abcdef")]);
        let (out, stats): (String, ExpandStats) = expand_line("%V:~1,3%", &env, &[], false);
        assert_eq!(out, "bcd");
        assert_eq!(stats.substrings, 1);
    }

    #[test]
    fn substring_negative_start() {
        let env: BTreeMap<String, String> = env_of(&[("V", "abcdef")]);
        let (out, _): (String, ExpandStats) = expand_line("%V:~-2%", &env, &[], false);
        assert_eq!(out, "ef");
    }

    #[test]
    fn substring_negative_len() {
        let env: BTreeMap<String, String> = env_of(&[("V", "abcdef")]);
        let (out, _): (String, ExpandStats) = expand_line("%V:~0,-2%", &env, &[], false);
        assert_eq!(out, "abcd");
    }

    #[test]
    fn substring_huge_positive_len_clamps_to_suffix() {
        let env: BTreeMap<String, String> = env_of(&[("V", "abcdef")]);
        let (out, _): (String, ExpandStats) =
            expand_line("%V:~1,9223372036854775807%", &env, &[], false);
        assert_eq!(out, "bcdef");
    }

    #[test]
    fn substring_min_negative_start_clamps_to_start() {
        let env: BTreeMap<String, String> = env_of(&[("V", "abcdef")]);
        let (out, _): (String, ExpandStats) =
            expand_line("%V:~-9223372036854775808%", &env, &[], false);
        assert_eq!(out, "abcdef");
    }

    #[test]
    fn substitution_replaces_all() {
        let env: BTreeMap<String, String> = env_of(&[("V", "a.b.c")]);
        let (out, stats): (String, ExpandStats) = expand_line("%V:.=-%", &env, &[], false);
        assert_eq!(out, "a-b-c");
        assert_eq!(stats.substitutions, 1);
    }

    #[test]
    fn substitution_delete() {
        let env: BTreeMap<String, String> = env_of(&[("V", "Xc:\\Xtemp")]);
        let (out, _): (String, ExpandStats) = expand_line("%V:X=%", &env, &[], false);
        assert_eq!(out, "c:\\temp");
    }

    #[test]
    fn tilde_name_and_ext() {
        let args: Vec<String> = vec!["c:\\dir\\sub\\file.exe".to_owned()];
        let (out, stats): (String, ExpandStats) =
            expand_line("%~n0%~x0", &env_of(&[]), &args, false);
        assert_eq!(out, "file.exe");
        assert_eq!(stats.tilde_params, 2);
    }

    #[test]
    fn tilde_drive_and_path() {
        let args: Vec<String> = vec!["c:\\dir\\sub\\file.exe".to_owned()];
        let (out, _): (String, ExpandStats) = expand_line("%~dp0", &env_of(&[]), &args, false);
        assert_eq!(out, "c:\\dir\\sub\\");
    }

    #[test]
    fn positional_arg() {
        let args: Vec<String> = vec!["script.bat".to_owned(), "first".to_owned()];
        let (out, _): (String, ExpandStats) = expand_line("%1", &env_of(&[]), &args, false);
        assert_eq!(out, "first");
    }

    #[test]
    fn nested_expansion_via_repeat() {
        let env: BTreeMap<String, String> = env_of(&[("A", "%B%"), ("B", "done")]);
        let (out, _): (String, ExpandStats) = expand_repeated("%A%", &env, &[], false, 4);
        assert_eq!(out, "done");
    }
}
