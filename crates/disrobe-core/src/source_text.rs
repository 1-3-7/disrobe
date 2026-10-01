use std::borrow::Cow;
use std::fmt::Write;

#[must_use]
pub const fn is_unsafe_in_source(c: char) -> bool {
    matches!(
        c,
        '\u{0000}'..='\u{001F}'
            | '\u{007F}'..='\u{009F}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

#[must_use]
pub fn escape_unsafe_chars(text: &str) -> Cow<'_, str> {
    if !text.chars().any(is_unsafe_in_source) {
        return Cow::Borrowed(text);
    }
    let mut out: String = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if is_unsafe_in_source(c) {
            let _: std::fmt::Result = write!(out, "\\u{{{:04X}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::{escape_unsafe_chars, is_unsafe_in_source};

    #[test]
    fn line_breaks_and_bidi_controls_become_visible_escapes() {
        assert_eq!(
            escape_unsafe_chars("Type\nName\u{202E}gpj.exe"),
            "Type\\u{000A}Name\\u{202E}gpj.exe"
        );
        assert_eq!(
            escape_unsafe_chars("a\u{2028}b\u{2066}c\r"),
            "a\\u{2028}b\\u{2066}c\\u{000D}"
        );
        assert_eq!(escape_unsafe_chars("\u{FEFF}Program"), "\\u{FEFF}Program");
    }

    #[test]
    fn deprecated_format_characters_obfuscators_hide_in_names_become_visible() {
        for c in '\u{206A}'..='\u{206F}' {
            assert!(is_unsafe_in_source(c), "U+{:04X}", u32::from(c));
        }
        assert_eq!(escape_unsafe_chars("a\u{206D}b"), "a\\u{206D}b");
    }

    #[test]
    fn ordinary_names_pass_through_unchanged_and_borrowed() {
        for name in [
            "System.Collections.Generic.List`1",
            "Überprüfung",
            "名前",
            "<Main>$",
        ] {
            assert!(
                matches!(escape_unsafe_chars(name), std::borrow::Cow::Borrowed(_)),
                "{name}"
            );
        }
        assert!(!is_unsafe_in_source('a'));
        assert!(!is_unsafe_in_source('\u{00E9}'));
    }
}
