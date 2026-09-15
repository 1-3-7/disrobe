use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use super::invoke_obfuscation::{reverse_string, reverse_token};

#[derive(Debug, Clone, Serialize)]
pub struct IseSteroidsReport {
    pub stripped_signature: bool,
    pub stripped_lookalike_chars: usize,
    pub output: String,
}

static ISE_SIG: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r"(?im)^#\s*SIG\s*#\s*Begin signature block[\s\S]*?#\s*SIG\s*#\s*End signature block",
    )
});

static HOMOGLYPH_RANGES: &[(char, char)] = &[
    ('\u{0400}', '\u{04FF}'),
    ('\u{2000}', '\u{206F}'),
    ('\u{FF00}', '\u{FFEF}'),
];

#[must_use]
pub fn reverse_isesteroids(input: &str) -> IseSteroidsReport {
    let mut stripped_sig: bool = false;
    let no_sig: String = if ISE_SIG.is_match(input) {
        stripped_sig = true;
        ISE_SIG.replace_all(input, "").into_owned()
    } else {
        input.to_owned()
    };
    let mut lookalike_count: usize = 0;
    let cleaned: String = no_sig
        .chars()
        .filter_map(|c: char| {
            if is_homoglyph(c) {
                lookalike_count += 1;
                ascii_equivalent(c)
            } else {
                Some(c)
            }
        })
        .collect();
    let after_string: String = reverse_string(&cleaned).output;
    let final_out: String = reverse_token(&after_string).output;
    IseSteroidsReport {
        stripped_signature: stripped_sig,
        stripped_lookalike_chars: lookalike_count,
        output: final_out,
    }
}

fn is_homoglyph(c: char) -> bool {
    HOMOGLYPH_RANGES.iter().any(|&(a, b)| c >= a && c <= b)
}

fn ascii_equivalent(c: char) -> Option<char> {
    let n: u32 = c as u32;
    Some(match c {
        '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' => '-',
        '\u{2018}' | '\u{2019}' | '\u{02BC}' => '\'',
        '\u{201C}' | '\u{201D}' => '"',
        '\u{00A0}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}' => ' ',
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(n - 0xFF00 + 0x20).unwrap_or(c),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_signature_block() {
        let src: &str =
            "Write-Host 'hi'\n# SIG # Begin signature block\nAAAA\n# SIG # End signature block\n";
        let r: IseSteroidsReport = reverse_isesteroids(src);
        assert!(r.stripped_signature);
        assert!(!r.output.contains("signature"));
    }

    #[test]
    fn replaces_homoglyphs() {
        let src: &str = "Get\u{2010}Process \u{2018}foo\u{2019}";
        let r: IseSteroidsReport = reverse_isesteroids(src);
        assert!(r.stripped_lookalike_chars >= 3);
        assert!(r.output.contains("Get-Process"));
    }
}
