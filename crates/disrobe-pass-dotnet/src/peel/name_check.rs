#![allow(clippy::doc_markdown)]
#[must_use]
pub fn is_non_random(name: &str) -> bool {
    let len: usize = name.chars().count();
    if len < 5 {
        return true;
    }
    let chars: Vec<char> = name.chars().collect();
    if chars.iter().all(|c: &char| !c.is_ascii_uppercase()) {
        return true;
    }
    if chars.iter().all(char::is_ascii_uppercase) {
        return true;
    }
    for i in 0..chars.len().saturating_sub(1) {
        if chars[i].is_ascii_digit() {
            return false;
        }
        if i > 0 && chars[i].is_ascii_uppercase() && chars[i - 1].is_ascii_uppercase() {
            return false;
        }
    }
    let words: Vec<String> = camel_words(&chars);
    let vowels: usize = words
        .iter()
        .filter(|w: &&String| w.chars().count() > 1 && has_vowel(w))
        .count();
    match words.len() {
        1 => vowels == words.len(),
        2 | 3 => vowels >= 1,
        4 | 5 => vowels >= 2,
        6 => vowels >= 3,
        7 => vowels >= 4,
        _ => vowels >= words.len().saturating_sub(4),
    }
}

#[must_use]
pub fn is_random(name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    let len: usize = chars.len();
    if len < 5 {
        return false;
    }
    let words: Vec<String> = type_words(&chars);
    if count_numbers(&words, 2) {
        return true;
    }
    let counts: TypeWordCounts = count_type_words(&words);
    if counts.upper >= 3 {
        return true;
    }
    let has_two_upper_words: bool = counts.upper == 2;
    for w in &words {
        if w.chars().count() > 1 {
            let Some(first): Option<char> = w.chars().next() else {
                continue;
            };
            if first.is_ascii_digit() {
                return true;
            }
        }
    }
    for i in 2..words.len() {
        let Some(c_prev): Option<char> = words[i - 1].chars().next() else {
            continue;
        };
        let Some(c_2): Option<char> = words[i - 2].chars().next() else {
            continue;
        };
        let Some(c_i): Option<char> = words[i].chars().next() else {
            continue;
        };
        if c_prev.is_ascii_digit() && c_2.is_ascii_lowercase() && c_i.is_ascii_lowercase() {
            return true;
        }
    }
    if has_two_upper_words && has_digit(&chars) {
        return true;
    }
    if len >= 3
        && chars[len - 3].is_ascii_lowercase()
        && chars[len - 2].is_ascii_uppercase()
        && chars[len - 1].is_ascii_digit()
    {
        return true;
    }
    false
}

fn has_vowel(s: &str) -> bool {
    s.chars().any(|c: char| {
        matches!(
            c,
            'a' | 'e' | 'i' | 'o' | 'u' | 'y' | 'A' | 'E' | 'I' | 'O' | 'U' | 'Y'
        )
    })
}

fn camel_words(chars: &[char]) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut current: String = String::new();
    for c in chars {
        if c.is_ascii_uppercase() && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(*c);
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn type_words(chars: &[char]) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut i: usize = 0;
    while i < chars.len() {
        let c: char = chars[i];
        let mut buf: String = String::new();
        if c.is_ascii_digit() {
            while i < chars.len() && chars[i].is_ascii_digit() {
                buf.push(chars[i]);
                i += 1;
            }
        } else if c.is_ascii_uppercase() {
            while i < chars.len() && chars[i].is_ascii_uppercase() {
                buf.push(chars[i]);
                i += 1;
            }
        } else if c.is_ascii_lowercase() {
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                buf.push(chars[i]);
                i += 1;
            }
        } else {
            while i < chars.len()
                && !(chars[i].is_ascii_digit()
                    || chars[i].is_ascii_uppercase()
                    || chars[i].is_ascii_lowercase())
            {
                buf.push(chars[i]);
                i += 1;
            }
        }
        if !buf.is_empty() {
            words.push(buf);
        }
    }
    words
}

#[derive(Debug, Default, Clone, Copy)]
struct TypeWordCounts {
    lower: u32,
    upper: u32,
    digits: u32,
}

fn count_type_words(words: &[String]) -> TypeWordCounts {
    let mut out: TypeWordCounts = TypeWordCounts::default();
    for w in words {
        if w.chars().count() <= 1 {
            continue;
        }
        let Some(c): Option<char> = w.chars().next() else {
            continue;
        };
        if c.is_ascii_digit() {
            out.digits += 1;
        } else if c.is_ascii_lowercase() {
            out.lower += 1;
        } else if c.is_ascii_uppercase() {
            out.upper += 1;
        }
    }
    out
}

fn count_numbers(words: &[String], threshold: u32) -> bool {
    let mut num: u32 = 0;
    for w in words {
        let Some(c): Option<char> = w.chars().next() else {
            continue;
        };
        if c.is_ascii_digit() {
            num += 1;
            if num >= threshold {
                return true;
            }
        }
    }
    false
}

fn has_digit(chars: &[char]) -> bool {
    chars.iter().any(char::is_ascii_digit)
}

#[must_use]
pub fn is_confuser_style(name: &str) -> bool {
    for c in name.chars() {
        let code: u32 = c as u32;
        if code < 0x20
            || (0xD800..=0xDFFF).contains(&code)
            || (0x200B..=0x200F).contains(&code)
            || (0x2028..=0x202F).contains(&code)
            || (0xE000..=0xF8FF).contains(&code)
            || code >= 0x10_FFFF
        {
            return true;
        }
    }
    if name.starts_with('_')
        && name[1..].chars().all(|c: char| c.is_ascii_digit())
        && name.len() >= 4
    {
        return true;
    }
    false
}

#[must_use]
pub fn is_smartassembly_style(name: &str) -> bool {
    name.starts_with("#=q") || name.starts_with("#=z")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn short_names_are_non_random() {
        assert!(is_non_random("abc"));
        assert!(is_non_random("Foo"));
    }

    #[test]
    fn human_camelcase_passes_non_random() {
        assert!(is_non_random("ParseFile"));
        assert!(is_non_random("Calculator"));
    }

    #[test]
    fn allcaps_short_is_non_random() {
        assert!(is_non_random("HTTPS"));
    }

    #[test]
    fn obvious_obfuscated_is_not_non_random() {
        assert!(!is_non_random("a1B2c3D4e5"));
    }

    #[test]
    fn random_detector_flags_multi_digit_pattern() {
        assert!(is_random("abc9d2"));
    }

    #[test]
    fn random_detector_misses_human() {
        assert!(!is_random("ParseHttpHeader"));
    }

    #[test]
    fn confuser_unprintable_flagged() {
        assert!(is_confuser_style("\u{200B}foo"));
    }

    #[test]
    fn confuser_underscore_digits_flagged() {
        assert!(is_confuser_style("_1234"));
    }

    #[test]
    fn smartassembly_q_prefix_flagged() {
        assert!(is_smartassembly_style("#=qABC123"));
    }
}
