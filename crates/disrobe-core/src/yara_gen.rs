use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::strings::{self, ExtractedString, Options, Tagging};
use crate::yara::{Rule, YaraParseError, YaraString, YaraStringKind, parse_rule};

pub const YARA_GEN_SCHEMA: &str = "disrobe.yara.generated/v0";

const MAX_STRINGS: usize = 20;
const MIN_STRING_LEN: usize = 6;
const MAX_STRING_LEN: usize = 96;
const MAGIC_PATTERN_LEN: usize = 8;
const HEX_LOWER: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];
const HEX_UPPER: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedRule {
    pub schema: &'static str,
    pub rule: Rule,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct GenerateOptions {
    pub name: String,
    pub sha256: Option<String>,
    pub date: Option<String>,
    pub max_strings: usize,
}

impl Default for GenerateOptions {
    #[inline]
    fn default() -> Self {
        Self {
            name: "disrobe_generated".to_owned(),
            sha256: None,
            date: None,
            max_strings: MAX_STRINGS,
        }
    }
}

#[derive(Debug, Error)]
pub enum YaraGenError {
    #[error("DR-YARAGEN-0001: generated rule failed to round-trip through the parser: {0}")]
    RoundTrip(#[from] YaraParseError),

    #[error("DR-YARAGEN-0002: rule name {name:?} is not a valid YARA identifier")]
    InvalidName { name: String },
}

pub type Result<T> = core::result::Result<T, YaraGenError>;

#[derive(Debug, Clone, Copy)]
struct MagicSignature {
    name: &'static str,
    magic: &'static [u8],
}

static MAGICS: &[MagicSignature] = &[
    MagicSignature {
        name: "pe",
        magic: b"MZ",
    },
    MagicSignature {
        name: "elf",
        magic: &[0x7f, b'E', b'L', b'F'],
    },
    MagicSignature {
        name: "macho_64",
        magic: &[0xcf, 0xfa, 0xed, 0xfe],
    },
    MagicSignature {
        name: "macho_32",
        magic: &[0xce, 0xfa, 0xed, 0xfe],
    },
    MagicSignature {
        name: "macho_fat",
        magic: &[0xca, 0xfe, 0xba, 0xbe],
    },
    MagicSignature {
        name: "zip",
        magic: b"PK\x03\x04",
    },
    MagicSignature {
        name: "pyc",
        magic: &[0x0d, 0x0d, 0x0a],
    },
    MagicSignature {
        name: "wasm",
        magic: b"\x00asm",
    },
    MagicSignature {
        name: "pdf",
        magic: b"%PDF",
    },
    MagicSignature {
        name: "gzip",
        magic: &[0x1f, 0x8b],
    },
    MagicSignature {
        name: "class",
        magic: &[0xca, 0xfe, 0xba, 0xbe],
    },
    MagicSignature {
        name: "dex",
        magic: b"dex\n",
    },
];

#[inline]
fn is_ident(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    name.chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn detect_magic(bytes: &[u8]) -> Option<MagicSignature> {
    MAGICS
        .iter()
        .find(|m: &&MagicSignature| bytes.starts_with(m.magic))
        .copied()
}

fn escape_text(value: &str) -> String {
    let mut out: String = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            c => {
                let mut buf: [u8; 4] = [0; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    push_hex_escape(&mut out, b);
                }
            }
        }
    }
    out
}

#[inline]
fn push_hex_escape(out: &mut String, byte: u8) {
    out.push('\\');
    out.push('x');
    push_hex_byte(out, byte, &HEX_LOWER);
}

#[inline]
fn push_hex_byte(out: &mut String, byte: u8, alphabet: &[char; 16]) {
    let high: usize = usize::from(byte >> 4);
    let low: usize = usize::from(byte & 0x0f);
    out.push(alphabet[high]);
    out.push(alphabet[low]);
}

fn hex_pattern(bytes: &[u8], len: usize) -> String {
    let take: usize = len.min(bytes.len());
    let mut out: String = String::with_capacity(take * 3);
    for (i, b) in bytes[..take].iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        push_hex_byte(&mut out, *b, &HEX_UPPER);
    }
    out
}

fn string_score(s: &ExtractedString) -> usize {
    let len_score: usize = s.value.len().min(MAX_STRING_LEN);
    let variety: usize = {
        let mut classes: u8 = 0;
        if s.value.chars().any(|c: char| c.is_ascii_lowercase()) {
            classes += 1;
        }
        if s.value.chars().any(|c: char| c.is_ascii_uppercase()) {
            classes += 1;
        }
        if s.value.chars().any(|c: char| c.is_ascii_digit()) {
            classes += 1;
        }
        if s.value.chars().any(|c: char| !c.is_ascii_alphanumeric()) {
            classes += 1;
        }
        classes as usize
    };
    let decode_bonus: usize = match s.tagging {
        Tagging::Plain { .. } => 0,
        _ => 8,
    };
    len_score + variety * 4 + decode_bonus
}

fn is_low_signal(value: &str) -> bool {
    let distinct: usize = {
        let mut seen: [bool; 256] = [false; 256];
        for b in value.bytes() {
            seen[b as usize] = true;
        }
        seen.iter().filter(|&&s: &&bool| s).count()
    };
    distinct < 4
}

fn select_strings(bytes: &[u8], max: usize) -> Vec<ExtractedString> {
    let opts: Options = Options {
        min_len: MIN_STRING_LEN,
        decode: true,
    };
    let mut all: Vec<ExtractedString> = strings::extract(bytes, opts)
        .into_iter()
        .filter(|s: &ExtractedString| {
            (MIN_STRING_LEN..=MAX_STRING_LEN).contains(&s.value.len()) && !is_low_signal(&s.value)
        })
        .collect();
    all.sort_by(|a: &ExtractedString, b: &ExtractedString| {
        string_score(b)
            .cmp(&string_score(a))
            .then_with(|| a.value.cmp(&b.value))
    });
    let mut chosen: Vec<ExtractedString> = Vec::new();
    for s in all {
        if chosen.len() >= max {
            break;
        }
        if chosen.iter().any(|c: &ExtractedString| c.value == s.value) {
            continue;
        }
        chosen.push(s);
    }
    chosen
}

fn build_rule(bytes: &[u8], opts: &GenerateOptions) -> Rule {
    let magic: Option<MagicSignature> = detect_magic(bytes);
    let selected: Vec<ExtractedString> = select_strings(bytes, opts.max_strings);

    let mut meta: BTreeMap<String, String> = BTreeMap::new();
    meta.insert(
        "generated_by".to_owned(),
        format!("disrobe {}", crate::VERSION),
    );
    meta.insert("schema".to_owned(), YARA_GEN_SCHEMA.to_owned());
    if let Some(sha) = opts.sha256.as_deref() {
        meta.insert("sha256".to_owned(), sha.to_owned());
    }
    if let Some(date) = opts.date.as_deref() {
        meta.insert("date".to_owned(), date.to_owned());
    }
    if let Some(m) = magic {
        meta.insert("format".to_owned(), m.name.to_owned());
    }

    let mut strings: Vec<YaraString> = Vec::new();
    if !bytes.is_empty() {
        strings.push(YaraString {
            id: "$magic".to_owned(),
            kind: YaraStringKind::Hex,
            value: hex_pattern(bytes, MAGIC_PATTERN_LEN),
            modifiers: Vec::new(),
        });
    }
    for (i, s) in selected.iter().enumerate() {
        strings.push(YaraString {
            id: format!("$s{i}"),
            kind: YaraStringKind::Text,
            value: escape_text(&s.value),
            modifiers: vec!["ascii".to_owned()],
        });
    }

    let condition: String = build_condition(magic.is_some() && !bytes.is_empty(), selected.len());

    Rule {
        name: opts.name.clone(),
        modifiers: Vec::new(),
        tags: vec!["disrobe".to_owned(), "generated".to_owned()],
        meta,
        strings,
        condition,
    }
}

fn build_condition(has_magic: bool, string_count: usize) -> String {
    let mut clauses: Vec<String> = Vec::new();
    if has_magic {
        clauses.push("$magic at 0".to_owned());
    }
    match string_count {
        0 => {}
        1 => clauses.push("$s0".to_owned()),
        n => {
            let threshold: usize = n.div_ceil(2).max(1);
            clauses.push(format!("{threshold} of ($s*)"));
        }
    }
    if clauses.is_empty() {
        "filesize > 0".to_owned()
    } else {
        clauses.join(" and ")
    }
}

fn render_rule(rule: &Rule) -> String {
    let mut out: String = String::new();
    let tags: String = if rule.tags.is_empty() {
        String::new()
    } else {
        format!(" : {}", rule.tags.join(" "))
    };
    out.push_str("rule ");
    out.push_str(&rule.name);
    out.push_str(&tags);
    out.push_str(" {\n");

    if !rule.meta.is_empty() {
        out.push_str("    meta:\n");
        for (k, v) in &rule.meta {
            let escaped: String = escape_text(v);
            out.push_str("        ");
            out.push_str(k);
            out.push_str(" = \"");
            out.push_str(&escaped);
            out.push_str("\"\n");
        }
    }

    if !rule.strings.is_empty() {
        out.push_str("    strings:\n");
        for s in &rule.strings {
            match s.kind {
                YaraStringKind::Text => {
                    let mods: String = render_modifiers(&s.modifiers);
                    out.push_str("        ");
                    out.push_str(&s.id);
                    out.push_str(" = \"");
                    out.push_str(&s.value);
                    out.push('"');
                    out.push_str(&mods);
                    out.push('\n');
                }
                YaraStringKind::Hex => {
                    out.push_str("        ");
                    out.push_str(&s.id);
                    out.push_str(" = { ");
                    out.push_str(&s.value);
                    out.push_str(" }\n");
                }
                YaraStringKind::Regex => {
                    let mods: String = render_modifiers(&s.modifiers);
                    out.push_str("        ");
                    out.push_str(&s.id);
                    out.push_str(" = /");
                    out.push_str(&s.value);
                    out.push('/');
                    out.push_str(&mods);
                    out.push('\n');
                }
            }
        }
    }

    out.push_str("    condition:\n");
    out.push_str("        ");
    out.push_str(&rule.condition);
    out.push_str("\n}\n");
    out
}

fn render_modifiers(modifiers: &[String]) -> String {
    if modifiers.is_empty() {
        String::new()
    } else {
        format!(" {}", modifiers.join(" "))
    }
}

pub fn generate(bytes: &[u8], opts: &GenerateOptions) -> Result<GeneratedRule> {
    if !is_ident(&opts.name) {
        return Err(YaraGenError::InvalidName {
            name: opts.name.clone(),
        });
    }
    let rule: Rule = build_rule(bytes, opts);
    let source: String = render_rule(&rule);
    let parsed: Rule = parse_rule(&source)?;
    Ok(GeneratedRule {
        schema: YARA_GEN_SCHEMA,
        rule: parsed,
        source,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::yara::parse_ruleset;

    #[test]
    fn generated_rule_round_trips_through_parser() {
        let bytes: &[u8] =
            b"MZ\x90\x00\x03\x00\x00\x00this_is_a_distinctive_marker_string KERNEL32.DLL CreateRemoteThread";
        let generated: GeneratedRule =
            generate(bytes, &GenerateOptions::default()).expect("generate");
        let reparsed: Rule = parse_rule(&generated.source).expect("source must parse");
        assert_eq!(reparsed.name, "disrobe_generated");
        assert!(!reparsed.condition.is_empty());
        assert_eq!(generated.rule.name, reparsed.name);
    }

    #[test]
    fn detects_pe_magic_and_emits_hex_at_zero() {
        let bytes: &[u8] = b"MZ\x90\x00\x03distinctive_signal_token AnotherDistinctToken";
        let generated: GeneratedRule =
            generate(bytes, &GenerateOptions::default()).expect("generate");
        assert!(
            generated.source.contains("$magic = {"),
            "{}",
            generated.source
        );
        assert!(
            generated.source.contains("$magic at 0"),
            "{}",
            generated.source
        );
        assert_eq!(
            generated.rule.meta.get("format").map(String::as_str),
            Some("pe")
        );
    }

    #[test]
    fn high_signal_strings_are_selected() {
        let bytes: &[u8] =
            b"\x00uniqueMalwareConfigKey1234 \x00SecondDistinctiveIndicator \x00aaaa";
        let generated: GeneratedRule =
            generate(bytes, &GenerateOptions::default()).expect("generate");
        assert!(
            generated.source.contains("uniqueMalwareConfigKey1234"),
            "{}",
            generated.source
        );
        assert!(
            !generated.source.contains("aaaa"),
            "low-signal string leaked: {}",
            generated.source
        );
    }

    #[test]
    fn custom_name_and_meta_are_applied() {
        let opts: GenerateOptions = GenerateOptions {
            name: "MyRule_v2".to_owned(),
            sha256: Some("deadbeef".to_owned()),
            date: Some("2026-06-10".to_owned()),
            max_strings: 10,
        };
        let generated: GeneratedRule =
            generate(b"some_distinctive_payload_marker here", &opts).expect("generate");
        assert_eq!(generated.rule.name, "MyRule_v2");
        assert_eq!(
            generated.rule.meta.get("sha256").map(String::as_str),
            Some("deadbeef")
        );
        assert_eq!(
            generated.rule.meta.get("date").map(String::as_str),
            Some("2026-06-10")
        );
        assert!(
            generated.source.contains("rule MyRule_v2 :"),
            "{}",
            generated.source
        );
    }

    #[test]
    fn invalid_name_is_rejected() {
        let opts: GenerateOptions = GenerateOptions {
            name: "9bad-name".to_owned(),
            ..GenerateOptions::default()
        };
        let err: YaraGenError = generate(b"payload data", &opts).expect_err("must reject");
        assert!(matches!(err, YaraGenError::InvalidName { .. }));
    }

    #[test]
    fn empty_input_still_valid_rule() {
        let generated: GeneratedRule =
            generate(b"", &GenerateOptions::default()).expect("generate");
        let reparsed: Rule = parse_rule(&generated.source).expect("parse");
        assert_eq!(reparsed.condition, "filesize > 0");
    }

    #[test]
    fn special_characters_in_strings_are_escaped() {
        let bytes: &[u8] = b"path\\with\"quotes and tabs distinctive_marker_xyz";
        let generated: GeneratedRule =
            generate(bytes, &GenerateOptions::default()).expect("generate");
        let _: Rule = parse_rule(&generated.source).expect("escaped source must parse");
    }

    #[test]
    fn output_parses_as_full_ruleset() {
        let generated: GeneratedRule = generate(
            b"MZ a_distinct_marker_token and_more_signal",
            &GenerateOptions::default(),
        )
        .expect("generate");
        let ruleset: crate::yara::YaraRuleset =
            parse_ruleset(&generated.source).expect("ruleset parse");
        assert_eq!(ruleset.rules.len(), 1);
    }

    #[test]
    fn report_serializes_with_schema() {
        let generated: GeneratedRule = generate(
            b"distinctive_marker_alpha distinctive_marker_beta",
            &GenerateOptions::default(),
        )
        .expect("generate");
        let value: serde_json::Value = serde_json::to_value(&generated).expect("serialize");
        assert_eq!(value["schema"], serde_json::json!(YARA_GEN_SCHEMA));
        assert!(value["source"].is_string());
        assert!(value["rule"]["name"].is_string());
    }
}
