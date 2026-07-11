use std::collections::BTreeMap;
use std::io::Read;

use disrobe_core::codec::{Base64Alphabet, Base64Padding, base64_decode as core_base64_decode};
use serde::Serialize;

use crate::error::{Error, Result};

type BatchVars = BTreeMap<String, String>;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const MAX_INFLATE_BYTES: usize = 1usize << 26;
const MAX_INFLATE_READ_BYTES: u64 = (1u64 << 26) + 1u64;
const MAX_BASE64_INPUT_BYTES: usize = (MAX_INFLATE_BYTES / 3usize) * 4usize + 4usize;
const MAX_BASE64_CHUNK_BYTES: usize = 1usize << 22;
const MAX_LAYERS: usize = 16usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WinScriptLang {
    PowerShell,
    Batch,
    VbScript,
}

impl WinScriptLang {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::PowerShell => "powershell",
            Self::Batch => "batch",
            Self::VbScript => "vbscript",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WinTechnique {
    EncodedCommand,
    GzipInflate,
    DeflateInflate,
    CharCodeJoin,
    StringConcat,
    FormatOperator,
    BacktickEscape,
    CaretEscape,
    XorWrapper,
    SecureStringPlaintext,
    Base64Blob,
    ReplaceTransform,
    StringReverse,
    BatchVarSubstring,
    CharBuilderConcat,
    EmbeddedPeBlob,
}

impl WinTechnique {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::EncodedCommand => "encoded-command",
            Self::GzipInflate => "gzip-inflate",
            Self::DeflateInflate => "deflate-inflate",
            Self::CharCodeJoin => "char-code-join",
            Self::StringConcat => "string-concat",
            Self::FormatOperator => "format-operator",
            Self::BacktickEscape => "backtick-escape",
            Self::CaretEscape => "caret-escape",
            Self::XorWrapper => "xor-wrapper",
            Self::SecureStringPlaintext => "securestring-plaintext",
            Self::Base64Blob => "base64-blob",
            Self::ReplaceTransform => "replace-transform",
            Self::StringReverse => "string-reverse",
            Self::BatchVarSubstring => "batch-var-substring",
            Self::CharBuilderConcat => "char-builder-concat",
            Self::EmbeddedPeBlob => "embedded-pe-blob",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveredLayer {
    pub technique: WinTechnique,
    pub recovered: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WallReason {
    RuntimeOnlyKey,
    RuntimeGeneratedString,
}

impl WallReason {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::RuntimeOnlyKey => "runtime-only-key",
            Self::RuntimeGeneratedString => "runtime-generated-string",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WinWall {
    pub technique: WinTechnique,
    pub reason: WallReason,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WinScriptRecovery {
    pub language: WinScriptLang,
    pub techniques: Vec<WinTechnique>,
    pub layers: Vec<RecoveredLayer>,
    pub walls: Vec<WinWall>,
    pub recovered_text: String,
}

impl WinScriptRecovery {
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        !self.techniques.is_empty()
    }
}

#[must_use]
pub fn classify(text: &str) -> Option<WinScriptLang> {
    let lower: String = text.to_ascii_lowercase();
    if is_strong_batch(&lower) {
        return Some(WinScriptLang::Batch);
    }
    if is_powershell(&lower) {
        return Some(WinScriptLang::PowerShell);
    }
    if is_vbscript(&lower) {
        return Some(WinScriptLang::VbScript);
    }
    if is_batch(&lower) {
        return Some(WinScriptLang::Batch);
    }
    None
}

fn is_strong_batch(lower: &str) -> bool {
    const STRONG: &[&str] = &["@echo off", "@echo on", "setlocal", "goto :eof"];
    let strong_hits: usize = STRONG
        .iter()
        .filter(|m: &&&str| lower.contains(**m))
        .count();
    if strong_hits == 0 {
        return false;
    }
    strong_hits >= 1
        && (has_batch_var_expansion(lower) || lower.contains("set ") || lower.contains("call "))
}

fn has_batch_var_expansion(lower: &str) -> bool {
    let bytes: &[u8] = lower.as_bytes();
    let mut i: usize = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_') {
            let mut j: usize = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'%' || bytes[j] == b':') {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_powershell(lower: &str) -> bool {
    const MARKERS: &[&str] = &[
        "-encodedcommand",
        "frombase64string",
        "new-object",
        "write-host",
        "invoke-expression",
        "iex ",
        "iex(",
        "[convert]::",
        "[system.",
        "[text.encoding]",
        "powershell -",
        "powershell.exe",
        "$psversiontable",
        "convertto-securestring",
        "[char[]]",
        "[char]",
        "[scriptblock]",
    ];
    const VERBS: &[&str] = &[
        "get-",
        "set-",
        "new-",
        "invoke-",
        "start-",
        "stop-",
        "out-",
        "where-",
        "foreach-",
        "select-",
        "add-",
        "remove-",
        "import-",
        "export-",
        "convert-",
        "convertto-",
        "convertfrom-",
        "write-",
        "read-",
    ];
    if MARKERS.iter().any(|m: &&str| lower.contains(m)) {
        return true;
    }
    let has_verb_noun: bool = VERBS.iter().any(|v: &&str| lower.contains(v));
    let has_var_assign: bool = has_ps_var_assignment(lower);
    let has_invoke_var: bool =
        lower.contains("& $") || lower.contains("&$") || lower.contains(". $");
    has_verb_noun
        || (has_var_assign
            && (has_invoke_var
                || lower.contains("'+'")
                || lower.contains("\"+\"")
                || lower.contains(" -f ")))
}

fn has_ps_var_assignment(lower: &str) -> bool {
    let bytes: &[u8] = lower.as_bytes();
    let mut i: usize = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_') {
            let mut j: usize = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_vbscript(lower: &str) -> bool {
    const MARKERS: &[&str] = &[
        "createobject",
        "wscript.",
        "dim ",
        "set ",
        "executeglobal",
        "chrw(",
        "msgbox",
        "vbscript",
    ];
    MARKERS.iter().any(|m: &&str| lower.contains(m))
}

fn is_batch(lower: &str) -> bool {
    const MARKERS: &[&str] = &[
        "@echo off",
        "setlocal",
        "set /a",
        "%comspec%",
        "goto :",
        "if exist ",
        "for /f ",
    ];
    MARKERS.iter().any(|m: &&str| lower.contains(m)) || lower.contains('^')
}

#[must_use]
pub fn looks_like_winscript(text: &str) -> bool {
    classify(text).is_some()
}

pub fn analyze(bytes: &[u8]) -> Result<WinScriptRecovery> {
    let text: String = decode_text(bytes);
    let Some(language): Option<WinScriptLang> = classify(&text) else {
        return Err(Error::Unrecognized);
    };
    Ok(recover(language, &text))
}

#[must_use]
pub fn decode_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
        return decode_utf16le(&bytes[2..]);
    }
    if looks_like_utf16le(bytes) {
        return decode_utf16le(bytes);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let zeros: usize = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .take(64)
        .filter(|b: &&u8| **b == 0)
        .count();
    let sampled: usize = bytes.iter().skip(1).step_by(2).take(64).count();
    sampled > 0 && zeros * 2 >= sampled
}

#[must_use]
pub fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[must_use]
pub fn recover(language: WinScriptLang, text: &str) -> WinScriptRecovery {
    let mut layers: Vec<RecoveredLayer> = Vec::new();
    let mut walls: Vec<WinWall> = Vec::new();
    let mut techniques: Vec<WinTechnique> = Vec::new();

    let escaped: String = match language {
        WinScriptLang::PowerShell => {
            let stripped: String = strip_backticks(text);
            if stripped != *text {
                push_unique(&mut techniques, WinTechnique::BacktickEscape);
                layers.push(RecoveredLayer {
                    technique: WinTechnique::BacktickEscape,
                    recovered: stripped.clone(),
                });
            }
            stripped
        }
        WinScriptLang::Batch => {
            let stripped: String = strip_carets(text);
            if stripped != *text {
                push_unique(&mut techniques, WinTechnique::CaretEscape);
                layers.push(RecoveredLayer {
                    technique: WinTechnique::CaretEscape,
                    recovered: stripped.clone(),
                });
            }
            if let Some(resolved) = resolve_batch_substrings(&stripped) {
                push_unique(&mut techniques, WinTechnique::BatchVarSubstring);
                layers.push(RecoveredLayer {
                    technique: WinTechnique::BatchVarSubstring,
                    recovered: resolved.clone(),
                });
                resolved
            } else {
                stripped
            }
        }
        WinScriptLang::VbScript => text.to_owned(),
    };

    let mut current: String = escaped;

    reassemble_syntactic(&mut current, &mut techniques, &mut layers);

    let mut layer_guard: usize = 0usize;
    while layer_guard < MAX_LAYERS {
        layer_guard += 1;
        let before: String = current.clone();

        reassemble_syntactic(&mut current, &mut techniques, &mut layers);

        if let Some(decoded) = decode_encoded_command(&current) {
            push_unique(&mut techniques, WinTechnique::EncodedCommand);
            layers.push(RecoveredLayer {
                technique: WinTechnique::EncodedCommand,
                recovered: decoded.clone(),
            });
            current = decoded;
            continue;
        }

        match inflate_base64_payload(&current) {
            PayloadResult::Inflated { technique, text } => {
                push_unique(&mut techniques, technique);
                layers.push(RecoveredLayer {
                    technique,
                    recovered: text.clone(),
                });
                current = text;
                continue;
            }
            PayloadResult::Xor { text } => {
                push_unique(&mut techniques, WinTechnique::XorWrapper);
                layers.push(RecoveredLayer {
                    technique: WinTechnique::XorWrapper,
                    recovered: text.clone(),
                });
                current = text;
                continue;
            }
            PayloadResult::PlainBase64 { text } => {
                push_unique(&mut techniques, WinTechnique::Base64Blob);
                layers.push(RecoveredLayer {
                    technique: WinTechnique::Base64Blob,
                    recovered: text.clone(),
                });
                current = text;
                continue;
            }
            PayloadResult::RuntimeKey { detail } => {
                push_unique(&mut techniques, WinTechnique::XorWrapper);
                walls.push(WinWall {
                    technique: WinTechnique::XorWrapper,
                    reason: WallReason::RuntimeOnlyKey,
                    detail,
                });
            }
            PayloadResult::None => {}
        }

        if current == before {
            break;
        }
    }

    if let Some(detail) = detect_embedded_pe(&current) {
        push_unique(&mut techniques, WinTechnique::EmbeddedPeBlob);
        layers.push(RecoveredLayer {
            technique: WinTechnique::EmbeddedPeBlob,
            recovered: detail,
        });
    }

    if let Some(secret) = recover_securestring_plaintext(&current) {
        push_unique(&mut techniques, WinTechnique::SecureStringPlaintext);
        layers.push(RecoveredLayer {
            technique: WinTechnique::SecureStringPlaintext,
            recovered: secret.clone(),
        });
        current.push('\n');
        current.push_str(&secret);
    } else if mentions_runtime_securestring(&current) {
        push_unique(&mut techniques, WinTechnique::SecureStringPlaintext);
        walls.push(WinWall {
            technique: WinTechnique::SecureStringPlaintext,
            reason: WallReason::RuntimeOnlyKey,
            detail: "ConvertTo-SecureString key/entropy supplied at runtime".to_owned(),
        });
    }

    techniques.sort_by_key(|t: &WinTechnique| t.tag());
    techniques.dedup();

    WinScriptRecovery {
        language,
        techniques,
        layers,
        walls,
        recovered_text: current,
    }
}

fn push_unique(techniques: &mut Vec<WinTechnique>, t: WinTechnique) {
    if !techniques.contains(&t) {
        techniques.push(t);
    }
}

fn reassemble_syntactic(
    current: &mut String,
    techniques: &mut Vec<WinTechnique>,
    layers: &mut Vec<RecoveredLayer>,
) {
    if let Some(rebuilt) = rebuild_char_builder(current) {
        push_unique(techniques, WinTechnique::CharBuilderConcat);
        layers.push(RecoveredLayer {
            technique: WinTechnique::CharBuilderConcat,
            recovered: rebuilt.clone(),
        });
        *current = rebuilt;
    }
    if let Some(rebuilt) = rebuild_string_concat(current) {
        push_unique(techniques, WinTechnique::StringConcat);
        layers.push(RecoveredLayer {
            technique: WinTechnique::StringConcat,
            recovered: rebuilt.clone(),
        });
        *current = rebuilt;
    }
    if let Some(rebuilt) = rebuild_format_operator(current) {
        push_unique(techniques, WinTechnique::FormatOperator);
        layers.push(RecoveredLayer {
            technique: WinTechnique::FormatOperator,
            recovered: rebuilt.clone(),
        });
        *current = rebuilt;
    }
    if let Some(rebuilt) = rebuild_replace(current) {
        push_unique(techniques, WinTechnique::ReplaceTransform);
        layers.push(RecoveredLayer {
            technique: WinTechnique::ReplaceTransform,
            recovered: rebuilt.clone(),
        });
        *current = rebuilt;
    }
    if let Some(rebuilt) = rebuild_string_reverse(current) {
        push_unique(techniques, WinTechnique::StringReverse);
        layers.push(RecoveredLayer {
            technique: WinTechnique::StringReverse,
            recovered: rebuilt.clone(),
        });
        *current = rebuilt;
    }
    if let Some(rebuilt) = rebuild_char_codes(current) {
        push_unique(techniques, WinTechnique::CharCodeJoin);
        layers.push(RecoveredLayer {
            technique: WinTechnique::CharCodeJoin,
            recovered: rebuilt.clone(),
        });
        *current = rebuilt;
    }
}

#[must_use]
pub fn strip_backticks(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut chars: std::str::Chars<'_> = text.chars();
    while let Some(c) = chars.next() {
        if c == '`' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('0') => out.push('\0'),
                Some(next) => out.push(next),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[must_use]
pub fn strip_carets(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut chars: std::str::Chars<'_> = text.chars();
    while let Some(c) = chars.next() {
        if c == '^' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[must_use]
pub fn decode_encoded_command(text: &str) -> Option<String> {
    const FLAGS: &[&str] = &["-encodedcommand", "-enc ", "-encoded ", "-ec ", "-e "];
    let lower: String = text.to_ascii_lowercase();
    let flag_pos: usize = FLAGS
        .iter()
        .filter_map(|f: &&str| lower.find(f).map(|p: usize| p + f.len()))
        .min()?;
    let rest: &str = text.get(flag_pos..)?.trim_start();
    let token: &str = rest
        .split(|c: char| c.is_whitespace() || c == ';' || c == '|')
        .find(|s: &&str| !s.is_empty())?;
    let cleaned: String = token
        .trim_matches(|c: char| c == '"' || c == '\'')
        .to_owned();
    let decoded: Vec<u8> = base64_decode(&cleaned)?;
    if decoded.len() < 4 {
        return None;
    }
    let s: String = decode_utf16le(&decoded);
    if is_printable_script(&s) {
        Some(s)
    } else {
        None
    }
}

enum PayloadResult {
    Inflated {
        technique: WinTechnique,
        text: String,
    },
    Xor {
        text: String,
    },
    PlainBase64 {
        text: String,
    },
    RuntimeKey {
        detail: String,
    },
    None,
}

fn inflate_base64_payload(text: &str) -> PayloadResult {
    let lower: String = text.to_ascii_lowercase();
    for blob in base64_blobs(text) {
        let Some(raw): Option<Vec<u8>> = base64_decode(&blob) else {
            continue;
        };
        if raw.len() >= 2
            && raw[..2] == GZIP_MAGIC
            && let Some(s) = inflate_gzip(&raw)
        {
            return PayloadResult::Inflated {
                technique: WinTechnique::GzipInflate,
                text: s,
            };
        }
        if (lower.contains("deflatestream") || lower.contains("deflate"))
            && let Some(s) = inflate_deflate(&raw)
        {
            return PayloadResult::Inflated {
                technique: WinTechnique::DeflateInflate,
                text: s,
            };
        }
        if let Some(key) = literal_xor_key(&lower) {
            let xored: Vec<u8> = raw.iter().map(|b: &u8| b ^ key).collect();
            if is_printable_bytes(&xored) {
                return PayloadResult::Xor {
                    text: String::from_utf8_lossy(&xored).into_owned(),
                };
            }
        }
        if (lower.contains("-bxor") || lower.contains(" xor ")) && literal_xor_key(&lower).is_none()
        {
            return PayloadResult::RuntimeKey {
                detail: "XOR key not present as a literal in the artifact".to_owned(),
            };
        }
        if (lower.contains("frombase64string")
            || lower.contains("iex")
            || lower.contains("invoke-expression"))
            && is_printable_bytes(&raw)
        {
            let s: String = String::from_utf8_lossy(&raw).into_owned();
            if is_printable_script(&s) && s.trim() != text.trim() {
                return PayloadResult::PlainBase64 { text: s };
            }
        }
    }
    PayloadResult::None
}

fn inflate_gzip(raw: &[u8]) -> Option<String> {
    let reader: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(raw);
    read_inflate_text(reader)
}

fn inflate_deflate(raw: &[u8]) -> Option<String> {
    let reader: flate2::read::DeflateDecoder<&[u8]> = flate2::read::DeflateDecoder::new(raw);
    read_inflate_text(reader).or_else(|| {
        let reader: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(raw);
        read_inflate_text(reader)
    })
}

fn read_inflate_text<R: Read>(reader: R) -> Option<String> {
    let mut out: Vec<u8> = Vec::new();
    let mut limited: std::io::Take<R> = reader.take(MAX_INFLATE_READ_BYTES);
    let read: usize = match limited.read_to_end(&mut out) {
        Ok(read) => read,
        Err(_) => return None,
    };
    if read > MAX_INFLATE_BYTES
        || out.is_empty()
        || out.len() > MAX_INFLATE_BYTES
        || !is_printable_bytes(&out)
    {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn literal_xor_key(lower: &str) -> Option<u8> {
    let markers: [&str; 2] = ["-bxor", "xor"];
    for marker in markers {
        let mut search_from: usize = 0usize;
        while let Some(rel) = lower[search_from..].find(marker) {
            let pos: usize = search_from + rel + marker.len();
            search_from = pos;
            let tail: &str = &lower[pos..];
            if let Some(key) = first_int_literal(tail) {
                return Some(key);
            }
        }
    }
    None
}

fn first_int_literal(tail: &str) -> Option<u8> {
    let trimmed: &str = tail.trim_start_matches(|c: char| {
        c.is_whitespace() || c == '(' || c == '[' || c == 'b' || c == 'y' || c == 't' || c == 'e'
    });
    if let Some(hex) = trimmed.strip_prefix("0x") {
        let digits: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
        if !digits.is_empty() {
            return u8::from_str_radix(&digits, 16).ok();
        }
    }
    let digits: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits
        .parse::<u16>()
        .ok()
        .and_then(|v: u16| u8::try_from(v).ok())
}

#[must_use]
pub fn rebuild_string_concat(text: &str) -> Option<String> {
    let mut out: String = String::with_capacity(text.len());
    let bytes: &[u8] = text.as_bytes();
    let mut i: usize = 0usize;
    let mut changed: bool = false;
    while i < bytes.len() {
        let c: u8 = bytes[i];
        if c == b'\'' || c == b'"' {
            let Some((literal, end)): Option<(String, usize)> = read_quoted(bytes, i, c) else {
                out.push(c as char);
                i += 1;
                continue;
            };
            let mut combined: String = literal;
            let mut cursor: usize = end;
            loop {
                let after: usize = skip_concat_plus(bytes, cursor);
                if after == cursor {
                    break;
                }
                let next_quote: u8 = bytes[after];
                let Some((next_lit, next_end)): Option<(String, usize)> =
                    read_quoted(bytes, after, next_quote)
                else {
                    break;
                };
                combined.push_str(&next_lit);
                cursor = next_end;
                changed = true;
            }
            out.push('\'');
            out.push_str(&combined);
            out.push('\'');
            i = cursor;
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    changed.then_some(out)
}

fn read_quoted(bytes: &[u8], start: usize, quote: u8) -> Option<(String, usize)> {
    if start >= bytes.len() || bytes[start] != quote {
        return None;
    }
    let mut s: String = String::new();
    let mut i: usize = start + 1;
    while i < bytes.len() {
        let c: u8 = bytes[i];
        if c == quote {
            if i + 1 < bytes.len() && bytes[i + 1] == quote {
                s.push(quote as char);
                i += 2;
                continue;
            }
            return Some((s, i + 1));
        }
        s.push(c as char);
        i += 1;
    }
    None
}

fn skip_concat_plus(bytes: &[u8], from: usize) -> usize {
    let mut i: usize = from;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'&') {
        i += 1;
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i < bytes.len() && (bytes[i] == b'\'' || bytes[i] == b'"') {
            return i;
        }
    }
    from
}

#[must_use]
pub fn rebuild_format_operator(text: &str) -> Option<String> {
    let mut lower: String = text.to_ascii_lowercase();
    let mut changed: bool = false;
    let mut result: String = text.to_owned();
    let mut search: usize = 0usize;
    while let Some(rel) = lower.get(search..).and_then(|s: &str| s.find("-f ")) {
        let fmt_op: usize = search + rel;
        let Some((template, _tpl_start, tpl_end)): Option<(String, usize, usize)> =
            quoted_before(result.as_bytes(), fmt_op)
        else {
            search = fmt_op + 3;
            continue;
        };
        let args_str: &str = result[fmt_op + 3..].trim_start();
        let Some((args, consumed)): Option<(Vec<String>, usize)> = parse_format_args(args_str)
        else {
            search = fmt_op + 3;
            continue;
        };
        let Some(rendered): Option<String> = apply_format(&template, &args) else {
            search = fmt_op + 3;
            continue;
        };
        let tpl_start_quote: usize = find_quote_start(result.as_bytes(), tpl_end);
        let args_end: usize = fmt_op
            + 3
            + (args_str.as_ptr() as usize - result[fmt_op + 3..].as_ptr() as usize)
            + consumed;
        let (Some(prefix), Some(suffix)): (Option<&str>, Option<&str>) =
            (result.get(..tpl_start_quote), result.get(args_end..))
        else {
            search = fmt_op + 3;
            continue;
        };
        let mut rebuilt: String = String::with_capacity(result.len());
        rebuilt.push_str(prefix);
        rebuilt.push('\'');
        rebuilt.push_str(&rendered);
        rebuilt.push('\'');
        rebuilt.push_str(suffix);
        result = rebuilt;
        lower = result.to_ascii_lowercase();
        changed = true;
        search = 0usize;
    }
    changed.then_some(result)
}

fn find_quote_start(bytes: &[u8], close_quote_after: usize) -> usize {
    let Some(quote): Option<u8> = close_quote_after
        .checked_sub(1)
        .and_then(|idx: usize| bytes.get(idx).copied())
    else {
        return 0;
    };
    let mut i: usize = close_quote_after.saturating_sub(2);
    loop {
        if bytes.get(i) == Some(&quote) {
            return i;
        }
        if i == 0 {
            return 0;
        }
        i -= 1;
    }
}

fn quoted_before(bytes: &[u8], before: usize) -> Option<(String, usize, usize)> {
    let mut i: usize = before.min(bytes.len());
    while i > 0 && matches!(bytes.get(i - 1), Some(b' ' | b'\t')) {
        i -= 1;
    }
    if i == 0 {
        return None;
    }
    let quote: u8 = *bytes.get(i - 1)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let close: usize = i;
    let mut j: usize = close.checked_sub(2)?;
    loop {
        if bytes.get(j) == Some(&quote) {
            let slice: &[u8] = bytes.get(j + 1..close - 1)?;
            let inner: String = String::from_utf8_lossy(slice).into_owned();
            return Some((inner, j, close));
        }
        if j == 0 {
            return None;
        }
        j -= 1;
    }
}

fn parse_format_args(s: &str) -> Option<(Vec<String>, usize)> {
    let bytes: &[u8] = s.as_bytes();
    let mut args: Vec<String> = Vec::new();
    let mut i: usize = 0usize;
    let mut paren_wrapped: bool = false;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'(' {
        paren_wrapped = true;
        i += 1;
    }
    loop {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let c: u8 = bytes[i];
        if c == b')' {
            i += 1;
            break;
        }
        if c == b'\'' || c == b'"' {
            let (lit, end): (String, usize) = read_quoted(bytes, i, c)?;
            args.push(lit);
            i = end;
        } else {
            break;
        }
        let mut k: usize = i;
        while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
            k += 1;
        }
        if k < bytes.len() && bytes[k] == b',' {
            i = k;
            continue;
        }
        if paren_wrapped && k < bytes.len() && bytes[k] == b')' {
            i = k + 1;
        }
        break;
    }
    if args.is_empty() {
        return None;
    }
    Some((args, i))
}

fn apply_format(template: &str, args: &[String]) -> Option<String> {
    let mut out: String = String::with_capacity(template.len());
    let chars: Vec<char> = template.chars().collect();
    let mut i: usize = 0usize;
    let mut substituted: bool = false;
    while i < chars.len() {
        let c: char = chars[i];
        if c == '{' {
            if i + 1 < chars.len() && chars[i + 1] == '{' {
                out.push('{');
                i += 2;
                continue;
            }
            let mut j: usize = i + 1;
            let mut idx: String = String::new();
            while j < chars.len() && chars[j].is_ascii_digit() {
                idx.push(chars[j]);
                j += 1;
            }
            if j < chars.len() && chars[j] == '}' && !idx.is_empty() {
                let n: usize = idx.parse::<usize>().ok()?;
                out.push_str(args.get(n)?);
                substituted = true;
                i = j + 1;
                continue;
            }
            out.push(c);
            i += 1;
        } else if c == '}' && i + 1 < chars.len() && chars[i + 1] == '}' {
            out.push('}');
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    substituted.then_some(out)
}

#[must_use]
pub fn rebuild_replace(text: &str) -> Option<String> {
    let bytes: &[u8] = text.as_bytes();
    let lower: Vec<u8> = text.to_ascii_lowercase().into_bytes();
    let mut result: String = String::with_capacity(text.len());
    let mut i: usize = 0usize;
    let mut changed: bool = false;
    while i < bytes.len() {
        if (bytes[i] == b'\'' || bytes[i] == b'"')
            && let Some((literal, after)) = read_quoted(bytes, i, bytes[i])
        {
            let mut subject: String = literal;
            let mut cursor: usize = after;
            let mut applied: bool = false;
            while let Some((from, to, next)) = parse_replace_suffix(bytes, &lower, cursor) {
                if from.is_empty() {
                    break;
                }
                subject = subject.replace(&from, &to);
                cursor = next;
                applied = true;
            }
            if applied {
                result.push('\'');
                result.push_str(&subject);
                result.push('\'');
                changed = true;
                i = cursor;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    changed.then_some(result)
}

fn parse_replace_suffix(
    bytes: &[u8],
    lower: &[u8],
    after_subject: usize,
) -> Option<(String, String, usize)> {
    const METHOD: &[u8] = b"replace";
    const OPS: &[&[u8]] = &[b"-replace", b"-creplace", b"-ireplace"];
    let mut i: usize = after_subject;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b')') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        let mut j: usize = i + 1;
        if j + METHOD.len() <= lower.len() && &lower[j..j + METHOD.len()] == METHOD {
            j += METHOD.len();
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                return parse_replace_args(bytes, j + 1, true);
            }
        }
        return None;
    }
    for op in OPS {
        if i + op.len() <= lower.len() && &lower[i..i + op.len()] == *op {
            let mut j: usize = i + op.len();
            if j < bytes.len() && !matches!(bytes[j], b' ' | b'\t' | b'\'' | b'"') {
                continue;
            }
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            return parse_replace_args(bytes, j, false);
        }
    }
    None
}

fn parse_replace_args(bytes: &[u8], start: usize, paren: bool) -> Option<(String, String, usize)> {
    let mut i: usize = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i >= bytes.len() || !matches!(bytes[i], b'\'' | b'"') {
        return None;
    }
    let (from, after_from): (String, usize) = read_quoted(bytes, i, bytes[i])?;
    let mut j: usize = after_from;
    while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b',') {
        j += 1;
    }
    if j >= bytes.len() || !matches!(bytes[j], b'\'' | b'"') {
        return None;
    }
    let (to, after_to): (String, usize) = read_quoted(bytes, j, bytes[j])?;
    let mut k: usize = after_to;
    if paren {
        while k < bytes.len() && matches!(bytes[k], b' ' | b'\t') {
            k += 1;
        }
        if k < bytes.len() && bytes[k] == b')' {
            k += 1;
        } else {
            return None;
        }
    }
    Some((from, to, k))
}

#[must_use]
pub fn rebuild_string_reverse(text: &str) -> Option<String> {
    let bytes: &[u8] = text.as_bytes();
    let lower: Vec<u8> = text.to_ascii_lowercase().into_bytes();
    let mut result: String = String::with_capacity(text.len());
    let mut i: usize = 0usize;
    let mut changed: bool = false;
    while i < bytes.len() {
        if (bytes[i] == b'\'' || bytes[i] == b'"')
            && let Some((literal, after)) = read_quoted(bytes, i, bytes[i])
            && let Some(end) = match_reverse_suffix(bytes, &lower, after)
        {
            let reversed: String = literal.chars().rev().collect();
            result.push('\'');
            result.push_str(&reversed);
            result.push('\'');
            changed = true;
            i = end;
            continue;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    changed.then_some(result)
}

fn match_reverse_suffix(bytes: &[u8], lower: &[u8], after_subject: usize) -> Option<usize> {
    const JOIN: &[u8] = b"-join";
    let mut i: usize = after_subject;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b')') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'[' {
        return None;
    }
    i += 1;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] == b'1' {
        i += 2;
    } else {
        return None;
    }
    while i < bytes.len() && bytes[i] == b'.' {
        i += 1;
    }
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'-') {
        i += 1;
    }
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'$' | b'(' | b')'))
    {
        i += 1;
    }
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b']' {
        return None;
    }
    i += 1;
    let mut j: usize = i;
    while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b')') {
        j += 1;
    }
    if j + JOIN.len() <= lower.len() && &lower[j..j + JOIN.len()] == JOIN {
        j += JOIN.len();
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
            j += 1;
        }
        if j < bytes.len()
            && matches!(bytes[j], b'\'' | b'"')
            && let Some((sep, end)) = read_quoted(bytes, j, bytes[j])
            && sep.is_empty()
        {
            return Some(end);
        }
    }
    None
}

#[must_use]
pub fn rebuild_char_builder(text: &str) -> Option<String> {
    let bytes: &[u8] = text.as_bytes();
    let lower: Vec<u8> = text.to_ascii_lowercase().into_bytes();
    let mut result: String = String::with_capacity(text.len());
    let mut i: usize = 0usize;
    let mut changed: bool = false;
    while i < bytes.len() {
        if let Some((decoded, end)) = match_char_builder_run(bytes, &lower, i) {
            result.push('\'');
            result.push_str(&decoded);
            result.push('\'');
            i = end;
            changed = true;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    changed.then_some(result)
}

fn match_char_builder_run(bytes: &[u8], lower: &[u8], start: usize) -> Option<(String, usize)> {
    let mut decoded: String = String::new();
    let mut i: usize = start;
    let mut count: usize = 0usize;
    let mut last_end: usize = start;
    while let Some((value, after)) = match_char_call(bytes, lower, i) {
        let ch: char = char::from_u32(value)?;
        decoded.push(ch);
        count += 1;
        last_end = after;
        let mut j: usize = after;
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
            j += 1;
        }
        if j < bytes.len() && (bytes[j] == b'&' || bytes[j] == b'+') {
            j += 1;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            i = j;
        } else {
            break;
        }
    }
    if count < 2 {
        return None;
    }
    Some((decoded, last_end))
}

fn match_char_call(bytes: &[u8], lower: &[u8], start: usize) -> Option<(u32, usize)> {
    const PREFIXES: &[&[u8]] = &[b"chrw(", b"chr(", b"chr (", b"chrw ("];
    let mut header: usize = 0usize;
    for p in PREFIXES {
        if start + p.len() <= lower.len() && &lower[start..start + p.len()] == *p {
            header = p.len();
            break;
        }
    }
    if header == 0 {
        return None;
    }
    let mut i: usize = start + header;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    let vbs_hex: bool = i + 1 < bytes.len() && bytes[i] == b'&' && (bytes[i + 1] | 0x20) == b'h';
    let c_hex: bool = i + 1 < bytes.len() && bytes[i] == b'0' && (bytes[i + 1] | 0x20) == b'x';
    let hex: bool = vbs_hex || c_hex;
    if hex {
        i += 2;
    }
    let digit_start: usize = i;
    while i < bytes.len()
        && ((hex && bytes[i].is_ascii_hexdigit()) || (!hex && bytes[i].is_ascii_digit()))
    {
        i += 1;
    }
    if i == digit_start {
        return None;
    }
    let token: &str = std::str::from_utf8(&bytes[digit_start..i]).ok()?;
    let value: u32 = if hex {
        u32::from_str_radix(token, 16).ok()?
    } else {
        token.parse::<u32>().ok()?
    };
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b')' {
        return None;
    }
    Some((value, i + 1))
}

#[must_use]
pub fn resolve_batch_substrings(text: &str) -> Option<String> {
    let vars: BatchVars = collect_batch_vars(text);
    if vars.is_empty() {
        return None;
    }
    let bytes: &[u8] = text.as_bytes();
    let mut out: String = String::with_capacity(text.len());
    let mut i: usize = 0usize;
    let mut changed: bool = false;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some((expanded, end)) = expand_batch_var(bytes, i, &vars)
        {
            out.push_str(&expanded);
            i = end;
            changed = true;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    changed.then_some(out)
}

fn collect_batch_vars(text: &str) -> BatchVars {
    let mut vars: BatchVars = BatchVars::new();
    for line in text.lines() {
        let trimmed: &str = line.trim_start();
        let lower: String = trimmed.to_ascii_lowercase();
        let body: &str = if let Some(rest) = lower.strip_prefix("set ") {
            &trimmed[trimmed.len() - rest.len()..]
        } else {
            continue;
        };
        let body: &str = body.trim_start();
        let body: &str = body.strip_prefix("/a ").map_or(body, str::trim_start);
        let Some(eq): Option<usize> = body.find('=') else {
            continue;
        };
        let mut name: &str = body[..eq].trim();
        if let Some(stripped) = name.strip_prefix('"') {
            name = stripped;
        }
        let value: &str = body[eq + 1..].trim_end_matches(['\r', '"']);
        if name.is_empty()
            || name.contains(['~', ':', '%'])
            || name.contains(char::is_whitespace)
            || value.contains('%')
        {
            continue;
        }
        vars.insert(name.to_ascii_lowercase(), value.to_owned());
    }
    vars
}

fn expand_batch_var(bytes: &[u8], start: usize, vars: &BatchVars) -> Option<(String, usize)> {
    let mut i: usize = start + 1;
    let name_start: usize = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let name: String = String::from_utf8_lossy(&bytes[name_start..i]).to_ascii_lowercase();
    let value: &String = vars.get(&name)?;
    if i < bytes.len() && bytes[i] == b'%' {
        return Some((value.clone(), i + 1));
    }
    if i >= bytes.len() || bytes[i] != b':' {
        return None;
    }
    i += 1;
    if i >= bytes.len() || bytes[i] != b'~' {
        return None;
    }
    i += 1;
    let (offset, after_off): (isize, usize) = read_signed_int(bytes, i)?;
    let mut length: Option<isize> = None;
    let mut j: usize = after_off;
    if j < bytes.len() && bytes[j] == b',' {
        let (len_val, after_len): (isize, usize) = read_signed_int(bytes, j + 1)?;
        length = Some(len_val);
        j = after_len;
    }
    if j >= bytes.len() || bytes[j] != b'%' {
        return None;
    }
    let chars: Vec<char> = value.chars().collect();
    let total: isize = chars.len() as isize;
    let begin: isize = if offset < 0 {
        (total + offset).max(0)
    } else {
        offset.min(total)
    };
    let end: isize = match length {
        Some(len) if len < 0 => (total + len).max(begin),
        Some(len) => (begin + len).min(total),
        None => total,
    };
    if begin >= end {
        return Some((String::new(), j + 1));
    }
    let slice: String = chars[begin as usize..end as usize].iter().collect();
    Some((slice, j + 1))
}

fn read_signed_int(bytes: &[u8], start: usize) -> Option<(isize, usize)> {
    let mut i: usize = start;
    let mut neg: bool = false;
    if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
        neg = bytes[i] == b'-';
        i += 1;
    }
    let digit_start: usize = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == digit_start {
        return None;
    }
    let token: &str = std::str::from_utf8(&bytes[digit_start..i]).ok()?;
    let value: isize = token.parse::<isize>().ok()?;
    Some((if neg { -value } else { value }, i))
}

#[must_use]
pub fn detect_embedded_pe(text: &str) -> Option<String> {
    const PE_B64_PREFIXES: &[&str] = &["TVqQ", "TVoA", "TVpQ", "TVqA", "TVpB"];
    for blob in base64_blobs(text) {
        if PE_B64_PREFIXES.iter().any(|p: &&str| blob.starts_with(p))
            && let Some(raw) = base64_decode(&blob)
            && raw.len() >= 2
            && raw[0] == b'M'
            && raw[1] == b'Z'
        {
            return Some(format!(
                "MZ/PE executable, {} bytes base64-embedded",
                raw.len()
            ));
        }
    }
    None
}

#[must_use]
pub fn rebuild_char_codes(text: &str) -> Option<String> {
    let mut result: String = String::with_capacity(text.len());
    let bytes: &[u8] = text.as_bytes();
    let mut i: usize = 0usize;
    let mut changed: bool = false;
    while i < bytes.len() {
        if let Some((decoded, end)) = match_char_code_run(text, i) {
            result.push('\'');
            result.push_str(&decoded);
            result.push('\'');
            i = end;
            changed = true;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    changed.then_some(result)
}

fn match_char_code_run(text: &str, start: usize) -> Option<(String, usize)> {
    const PREFIXES: &[&str] = &[
        "[char[]](",
        "[char[]] (",
        "string.fromcharcode(",
        "fromcharcode(",
        "chr(",
        "chrw(",
        "[char]",
    ];
    let bytes: &[u8] = text.as_bytes();
    let lower: &[u8] = &text.to_ascii_lowercase().into_bytes()[start..];
    let mut header: usize = 0usize;
    for p in PREFIXES {
        if lower.len() >= p.len() && &lower[..p.len()] == p.as_bytes() {
            header = p.len();
            break;
        }
    }
    if header == 0 {
        return None;
    }
    let mut nums: Vec<u32> = Vec::new();
    let mut i: usize = start + header;
    loop {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b',' | b'+') {
            i += 1;
        }
        let num_start: usize = i;
        let mut hex: bool = false;
        if i + 1 < bytes.len() && bytes[i] == b'0' && (bytes[i + 1] | 0x20) == b'x' {
            hex = true;
            i += 2;
        }
        let digit_start: usize = i;
        while i < bytes.len()
            && ((hex && bytes[i].is_ascii_hexdigit()) || (!hex && bytes[i].is_ascii_digit()))
        {
            i += 1;
        }
        if i == digit_start {
            i = num_start;
            break;
        }
        let token: &str = &text[digit_start..i];
        let value: u32 = if hex {
            u32::from_str_radix(token, 16).ok()?
        } else {
            token.parse::<u32>().ok()?
        };
        nums.push(value);
        let mut k: usize = i;
        while k < bytes.len() && matches!(bytes[k], b' ' | b'\t') {
            k += 1;
        }
        if k < bytes.len() && (bytes[k] == b',' || bytes[k] == b'+') {
            i = k;
            continue;
        }
        break;
    }
    if nums.is_empty() {
        return None;
    }
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b')') {
        i += 1;
    }
    let lower_after: String = text[i..].to_ascii_lowercase();
    let mut consumed_join: usize = i;
    for suffix in ["-join''", "-join \"\"", "-join ''", "-join\"\""] {
        let s: String = lower_after.replace(' ', "");
        if s.starts_with(&suffix.replace(' ', "")) {
            consumed_join = i + suffix.len().min(text.len() - i);
            break;
        }
    }
    let decoded: String = nums
        .iter()
        .filter_map(|n: &u32| char::from_u32(*n))
        .collect();
    if decoded.is_empty() {
        return None;
    }
    Some((decoded, consumed_join.max(i)))
}

#[must_use]
pub fn recover_securestring_plaintext(text: &str) -> Option<String> {
    let lower: String = text.to_ascii_lowercase();
    if !lower.contains("convertto-securestring") {
        return None;
    }
    if !lower.contains("-asplaintext") {
        return None;
    }
    let bytes: &[u8] = text.as_bytes();
    let key_lower: &str = "convertto-securestring";
    let pos: usize = lower.find(key_lower)?;
    for q in [b'\'', b'"'] {
        let mut i: usize = pos;
        while i < bytes.len() {
            if bytes[i] == q {
                if let Some((lit, _end)) = read_quoted(bytes, i, q)
                    && !lit.trim().is_empty()
                {
                    return Some(lit);
                }
                break;
            }
            i += 1;
        }
    }
    None
}

fn mentions_runtime_securestring(text: &str) -> bool {
    let lower: String = text.to_ascii_lowercase();
    lower.contains("convertto-securestring")
        && !lower.contains("-asplaintext")
        && (lower.contains("-key") || lower.contains("get-content") || lower.contains("read-host"))
}

#[must_use]
pub fn base64_blobs(text: &str) -> Vec<String> {
    let bytes: &[u8] = text.as_bytes();
    let mut blobs: Vec<String> = Vec::new();
    let mut i: usize = 0usize;
    while i < bytes.len() {
        if is_b64_char(bytes[i]) {
            let start: usize = i;
            while i < bytes.len() && is_b64_char(bytes[i]) {
                i += 1;
            }
            let mut end: usize = i;
            while end < bytes.len() && bytes[end] == b'=' {
                end += 1;
            }
            let len: usize = end - start;
            if len >= 16usize && !base64_input_too_large(len) {
                blobs.push(text[start..end].to_owned());
            }
            i = end;
        } else {
            i += 1;
        }
    }
    blobs
}

fn is_b64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

#[must_use]
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    if base64_input_too_large(input.len()) {
        return None;
    }
    let mut cleaned: String = input
        .chars()
        .filter(|c: &char| !c.is_whitespace())
        .collect();
    if base64_input_too_large(cleaned.len()) {
        return None;
    }
    if cleaned.len() % 4usize == 1usize {
        return None;
    }
    let trimmed_len: usize = cleaned.trim_end_matches('=').len();
    let pad: usize = cleaned.len() - trimmed_len;
    if pad > 2 {
        return None;
    }
    if pad > 0usize && (trimmed_len == 0usize || !cleaned.len().is_multiple_of(4usize)) {
        return None;
    }
    if trimmed_len == 0usize {
        return Some(Vec::new());
    }
    cleaned.truncate(trimmed_len);
    let decoded_len: usize =
        (trimmed_len / 4usize) * 3usize + ((trimmed_len % 4usize) * 3usize) / 4usize;
    while !cleaned.len().is_multiple_of(4usize) {
        cleaned.push('A');
    }
    let mut out: Vec<u8> = Vec::with_capacity(decoded_len.saturating_add(2usize));
    for chunk in cleaned.as_bytes().chunks(MAX_BASE64_CHUNK_BYTES) {
        let decoded: Vec<u8> =
            core_base64_decode(chunk, Base64Alphabet::Standard, Base64Padding::Forbidden).ok()?;
        out.extend_from_slice(&decoded);
    }
    out.truncate(decoded_len);
    Some(out)
}

const fn base64_input_too_large(len: usize) -> bool {
    len > MAX_BASE64_INPUT_BYTES
}

fn is_printable_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable: usize = bytes
        .iter()
        .filter(|b: &&u8| (0x20..0x7f).contains(*b) || matches!(**b, b'\n' | b'\r' | b'\t'))
        .count();
    printable * 10 >= bytes.len() * 9
}

fn is_printable_script(s: &str) -> bool {
    !s.is_empty() && is_printable_bytes(s.as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn b64_roundtrip_matches_real() {
        let raw: Vec<u8> = base64_decode("aGVsbG8=").expect("decode");
        assert_eq!(raw, b"hello");
        assert_eq!(base64_decode("aGVsbG8"), Some(b"hello".to_vec()));
        assert_eq!(
            base64_decode("aG\u{2003}Vs\n bG8="),
            Some(b"hello".to_vec())
        );
        assert_eq!(base64_decode("AB"), Some(vec![0]));
    }

    #[test]
    fn b64_rejects_invalid_quantum_length() {
        assert!(base64_decode("A").is_none());
        assert!(base64_decode("=").is_none());
        assert!(base64_decode("AA=").is_none());
        assert!(base64_decode("A=AA").is_none());
        assert!(base64_decode("aGVsbG8===").is_none());
    }

    #[test]
    fn base64_size_guard_rejects_above_cap() {
        assert!(!base64_input_too_large(MAX_BASE64_INPUT_BYTES));
        assert!(base64_input_too_large(MAX_BASE64_INPUT_BYTES + 1usize));
        let encoded: String = "A".repeat(MAX_BASE64_CHUNK_BYTES + 4usize);
        let decoded: Vec<u8> = base64_decode(&encoded).expect("chunked decode");
        assert_eq!(decoded.len(), (encoded.len() / 4usize) * 3usize);
        assert!(decoded.iter().all(|byte: &u8| *byte == 0u8));
    }

    #[test]
    fn classify_powershell() {
        assert_eq!(
            classify("Invoke-Expression $payload"),
            Some(WinScriptLang::PowerShell)
        );
    }

    #[test]
    fn classify_rejects_plain() {
        assert!(classify("the quick brown fox jumps over").is_none());
    }

    #[test]
    fn strip_backticks_basic() {
        assert_eq!(strip_backticks("I`E`X"), "IEX");
        assert_eq!(strip_backticks("a`nb"), "a\nb");
    }

    #[test]
    fn strip_carets_basic() {
        assert_eq!(strip_carets("p^o^w^e^r^s^h^e^l^l"), "powershell");
    }

    #[test]
    fn gzip_inflate_rejects_oversize_output() {
        let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let chunk: [u8; 8192] = [b'A'; 8192];
        let mut remaining: usize = MAX_INFLATE_BYTES + 1usize;
        while remaining > 0usize {
            let n: usize = remaining.min(chunk.len());
            encoder.write_all(&chunk[..n]).expect("write gzip");
            remaining -= n;
        }
        let compressed: Vec<u8> = encoder.finish().expect("finish gzip");
        assert!(inflate_gzip(&compressed).is_none());
    }
}
