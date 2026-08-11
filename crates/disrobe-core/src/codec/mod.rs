pub mod aes_cbc;
pub mod alphabets;
pub mod base64;
pub mod cipher;
pub mod crc32;
pub mod crypto_wall;
pub mod framed;
pub mod hex;
pub mod web_escape;

use std::collections::BTreeMap;

use thiserror::Error;

pub use aes_cbc::{CbcPadding, aes_cbc_decrypt};
pub use alphabets::Base58Variant;
pub use base64::{Base64Alphabet, Base64Padding, base64_decode};
pub use cipher::{StreamCipher, TeaVariant};
pub use crc32::crc32_ieee;
pub use crypto_wall::{CryptoWall, CryptoWallKind, classify as classify_crypto_wall};
pub use hex::{decode as hex_decode, encode as hex_encode};

const ADLER_MODULUS: u32 = 65_521;
const ADLER_CHUNK_LEN: usize = 5_552;
const ADLER_ACCUMULATOR_MAX: u64 = u16::MAX as u64
    + ADLER_CHUNK_LEN as u64 * u16::MAX as u64
    + u8::MAX as u64 * ADLER_CHUNK_LEN as u64 * (ADLER_CHUNK_LEN as u64 + 1) / 2;
const _: () = assert!(ADLER_ACCUMULATOR_MAX <= u32::MAX as u64);

const MIN_CASCADE_INPUT: usize = 8;
const VALIDATE_PRINTABLE_RATIO: f64 = 0.90;
const VALIDATE_MIN_WORD_HITS: usize = 1;

#[must_use]
pub const fn adler32(seed: u32, bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return seed;
    }
    let mut low: u32 = seed & u16::MAX as u32;
    let mut high: u32 = seed >> 16;
    let mut offset: usize = 0;
    while offset < bytes.len() {
        let remaining: usize = bytes.len() - offset;
        let chunk_len: usize = if remaining > ADLER_CHUNK_LEN {
            ADLER_CHUNK_LEN
        } else {
            remaining
        };
        let chunk_end: usize = offset + chunk_len;
        while offset < chunk_end {
            low += bytes[offset] as u32;
            high += low;
            offset += 1;
        }
        low %= ADLER_MODULUS;
        high %= ADLER_MODULUS;
    }
    (high << 16) | low
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("input symbol {symbol:#04x} is outside the scheme alphabet")]
    InvalidSymbol { symbol: u8 },
    #[error("input length {len} is invalid for this scheme")]
    BadLength { len: usize },
    #[error("input length {len} exceeds the decode bound")]
    TooLarge { len: usize },
    #[error("required framing markers were absent")]
    MissingFrame,
    #[error("decoded value overflowed the scheme word width")]
    Overflow,
    #[error("block cipher or base64 padding was malformed")]
    BadPadding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Base58Bitcoin,
    Base58Ripple,
    Base62,
    Base45,
    Base91,
    Base92,
    Base122,
    Ascii85,
    Z85,
    UuEncode,
    XxEncode,
    YEnc,
    PercentUrl,
    HtmlEntity,
    Punycode,
    Base64Standard,
    Base64Url,
}

pub(crate) fn bytes_to_string(bytes: Vec<u8>) -> String {
    let mut out: String = String::with_capacity(bytes.len());
    for byte in bytes {
        out.push(char::from(byte));
    }
    out
}

impl Scheme {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Base58Bitcoin => "base58:bitcoin",
            Self::Base58Ripple => "base58:ripple",
            Self::Base62 => "base62",
            Self::Base45 => "base45",
            Self::Base91 => "base91",
            Self::Base92 => "base92",
            Self::Base122 => "base122",
            Self::Ascii85 => "ascii85",
            Self::Z85 => "z85",
            Self::UuEncode => "uuencode",
            Self::XxEncode => "xxencode",
            Self::YEnc => "yenc",
            Self::PercentUrl => "percent-url",
            Self::HtmlEntity => "html-entity",
            Self::Punycode => "punycode",
            Self::Base64Standard => "base64:standard",
            Self::Base64Url => "base64:url",
        }
    }

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Ascii85,
            Self::Z85,
            Self::UuEncode,
            Self::XxEncode,
            Self::YEnc,
            Self::PercentUrl,
            Self::HtmlEntity,
            Self::Punycode,
            Self::Base91,
            Self::Base92,
            Self::Base122,
            Self::Base58Bitcoin,
            Self::Base58Ripple,
            Self::Base62,
            Self::Base45,
            Self::Base64Standard,
            Self::Base64Url,
        ]
    }
}

pub fn decode(input: &[u8], scheme: Scheme) -> Result<Vec<u8>, DecodeError> {
    match scheme {
        Scheme::Base58Bitcoin => alphabets::base58_decode(input, Base58Variant::Bitcoin),
        Scheme::Base58Ripple => alphabets::base58_decode(input, Base58Variant::Ripple),
        Scheme::Base62 => alphabets::base62_decode(input),
        Scheme::Base45 => alphabets::base45_decode(input),
        Scheme::Base91 => alphabets::base91_decode(input),
        Scheme::Base92 => alphabets::base92_decode(input),
        Scheme::Base122 => alphabets::base122_decode(input),
        Scheme::Ascii85 => framed::ascii85_decode(input),
        Scheme::Z85 => framed::z85_decode(input),
        Scheme::UuEncode => framed::uudecode(input),
        Scheme::XxEncode => framed::xxdecode(input),
        Scheme::YEnc => framed::yenc_decode(input),
        Scheme::PercentUrl => Ok(web_escape::percent_decode_lenient(
            input,
            web_escape::PlusPolicy::Literal,
        )),
        Scheme::HtmlEntity => decode_text(input, web_escape::html_entity_decode),
        Scheme::Punycode => decode_text(input, |s: &str| {
            web_escape::punycode_decode(s).map(String::into_bytes)
        }),
        Scheme::Base64Standard => {
            base64_decode(input, Base64Alphabet::Standard, Base64Padding::Optional)
        }
        Scheme::Base64Url => base64_decode(input, Base64Alphabet::UrlSafe, Base64Padding::Optional),
    }
}

fn decode_text<F, T>(input: &[u8], f: F) -> Result<Vec<u8>, DecodeError>
where
    F: Fn(&str) -> Result<T, DecodeError>,
    T: Into<Vec<u8>>,
{
    let text: &str = core::str::from_utf8(input).map_err(|_| DecodeError::InvalidSymbol {
        symbol: input.first().copied().unwrap_or(0),
    })?;
    f(text).map(Into::into)
}

fn decode_text_string(input: &[u8], scheme: Scheme) -> Result<String, DecodeError> {
    let text: &str = core::str::from_utf8(input).map_err(|_| DecodeError::InvalidSymbol {
        symbol: input.first().copied().unwrap_or(0),
    })?;
    match scheme {
        Scheme::HtmlEntity => web_escape::html_entity_decode(text),
        Scheme::Punycode => web_escape::punycode_decode(text),
        _ => Err(DecodeError::MissingFrame),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeHit {
    pub scheme: Scheme,
    pub decoded: Vec<u8>,
    pub reason: ValidationReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationReason {
    NestedMagic,
    PyMarshal,
    PrintableText,
}

const NESTED_MAGICS: &[(&[u8], &str)] = &[
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"%PDF", "pdf"),
    (b"{\"", "json"),
    (b"<?xml", "xml"),
    (b"\x89PNG\r\n\x1a\n", "png"),
];

fn looks_like_py_marshal(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    let magic_tail: u16 = u16::from_le_bytes([bytes[2], bytes[3]]);
    if magic_tail != 0x0a0d {
        return false;
    }
    matches!(bytes[0], 0x42..=0xff) && bytes[1] < 0x10
}

fn nested_magic(bytes: &[u8]) -> bool {
    NESTED_MAGICS
        .iter()
        .any(|(magic, _): &(&[u8], &str)| bytes.starts_with(magic))
}

#[must_use]
pub fn nested_container_magic(bytes: &[u8]) -> bool {
    nested_magic(bytes) || bytes.starts_with(b"BZh") || bytes.starts_with(b"ustar")
}

fn validate(bytes: &[u8]) -> Option<ValidationReason> {
    if bytes.len() < 4 {
        return None;
    }
    if nested_magic(bytes) {
        return Some(ValidationReason::NestedMagic);
    }
    if looks_like_py_marshal(bytes) {
        return Some(ValidationReason::PyMarshal);
    }
    if printable_text(bytes) {
        return Some(ValidationReason::PrintableText);
    }
    None
}

fn printable_text(bytes: &[u8]) -> bool {
    let printable: usize = bytes
        .iter()
        .filter(|&&b: &&u8| matches!(b, 0x20..=0x7e | b'\t' | b'\n' | b'\r'))
        .count();
    if (printable as f64 / bytes.len() as f64) < VALIDATE_PRINTABLE_RATIO {
        return false;
    }
    let lower: String = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let hits: usize = WORDS.iter().filter(|w: &&&str| lower.contains(*w)).count();
    hits >= VALIDATE_MIN_WORD_HITS
}

const WORDS: &[&str] = &[
    "http",
    "https",
    "www",
    "the",
    "com",
    "exe",
    "dll",
    "powershell",
    "kernel",
    "system",
    "windows",
    "process",
    "user",
    "admin",
    "password",
    "token",
    "config",
    "import",
    "function",
    "select",
    "http://",
    "https://",
    "and",
    "for",
    "var",
    "def",
    "class",
];

#[must_use]
pub fn blind_cascade(input: &[u8]) -> Vec<CascadeHit> {
    if input.len() < MIN_CASCADE_INPUT || input.len() > (1 << 24) {
        return Vec::new();
    }
    let mut hits: Vec<CascadeHit> = Vec::new();
    for &scheme in Scheme::all() {
        let decoded: Vec<u8> = match scheme {
            Scheme::HtmlEntity | Scheme::Punycode => match decode_text_string(input, scheme) {
                Ok(text) if text.as_bytes() != input => text.into_bytes(),
                _ => continue,
            },
            _ => match decode(input, scheme) {
                Ok(bytes) if !bytes.is_empty() && bytes != input => bytes,
                _ => continue,
            },
        };
        if let Some(reason) = validate(&decoded) {
            hits.push(CascadeHit {
                scheme,
                decoded,
                reason,
            });
        }
    }
    hits
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CascadeRecovery {
    Decoded(Vec<CascadeHit>),
    Walled(crypto_wall::CryptoWall),
    Nothing,
}

#[must_use]
pub fn cascade_or_wall(input: &[u8]) -> CascadeRecovery {
    let hits: Vec<CascadeHit> = blind_cascade(input);
    if !hits.is_empty() {
        return CascadeRecovery::Decoded(hits);
    }
    crypto_wall::classify(input).map_or(CascadeRecovery::Nothing, CascadeRecovery::Walled)
}

const CUSTOM_B64_CRIBS: &[&[u8]] = &[
    &[0x4d, 0x5a],
    &[0x7f, 0x45, 0x4c, 0x46],
    &[0x50, 0x4b, 0x03, 0x04],
    &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    &[0xff, 0xfe],
    &[0x78, 0x9c],
    &[0x78, 0xda],
    &[0x1f, 0x8b, 0x08],
    &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
    &[0x42, 0x5a, 0x68],
    &[0x63],
];

const DARKGATE_ALPHA_V1: &[u8; 64] =
    b"+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const DARKGATE_ALPHA_V2: &[u8; 64] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomB64Match {
    pub alphabet_label: &'static str,
    pub crib_name: &'static str,
    pub decoded: Vec<u8>,
}

fn custom_b64_crib_sniff(data: &[u8]) -> Option<&'static str> {
    const CRIB_NAMES: &[&str] = &[
        "pe-mz",
        "elf",
        "zip",
        "png",
        "utf-16le",
        "zlib-default",
        "zlib-best",
        "gzip",
        "xz",
        "bz2",
        "marshal-code",
    ];
    for (crib, name) in CUSTOM_B64_CRIBS.iter().zip(CRIB_NAMES.iter()) {
        if data.len() >= crib.len() && &data[..crib.len()] == *crib {
            return Some(name);
        }
    }
    None
}

const CUSTOM_BASE64_UNMAPPED: u8 = u8::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomBase64GroupPolicy {
    KeepPartial,
    DropPartial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomBase64Input<'a> {
    Bytes(&'a [u8]),
    Text(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CustomBase64AlphabetKind<'a> {
    ByteTable(Box<[u8; 256]>),
    BorrowedCharacterMap(&'a BTreeMap<char, u8>),
    OwnedCharacterMap(BTreeMap<char, u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomBase64Alphabet<'a> {
    kind: CustomBase64AlphabetKind<'a>,
}

impl CustomBase64Alphabet<'static> {
    fn from_legacy_byte_symbols(symbols: &[u8; 64]) -> Self {
        let mut table: [u8; 256] = [CUSTOM_BASE64_UNMAPPED; 256];
        for (value, symbol) in symbols.iter().copied().enumerate() {
            table[usize::from(symbol)] = value as u8;
        }
        Self {
            kind: CustomBase64AlphabetKind::ByteTable(Box::new(table)),
        }
    }

    fn from_byte_entries(entries: impl IntoIterator<Item = (u8, u8)>) -> Option<Self> {
        let mut table: [u8; 256] = [CUSTOM_BASE64_UNMAPPED; 256];
        let mut count: usize = 0;
        for (symbol, value) in entries {
            if count >= 64 {
                return None;
            }
            if symbol == b'=' || value >= 64 {
                return None;
            }
            let slot: &mut u8 = &mut table[usize::from(symbol)];
            if *slot != CUSTOM_BASE64_UNMAPPED {
                return None;
            }
            *slot = value;
            count = count.checked_add(1)?;
        }
        if count == 0 {
            return None;
        }
        Some(Self {
            kind: CustomBase64AlphabetKind::ByteTable(Box::new(table)),
        })
    }

    #[must_use]
    pub fn from_byte_symbols(symbols: &[u8; 64]) -> Option<Self> {
        Self::from_byte_entries(
            symbols
                .iter()
                .copied()
                .enumerate()
                .map(|(value, symbol): (usize, u8)| (symbol, value as u8)),
        )
    }

    #[must_use]
    pub fn from_byte_pairs(pairs: &[(u8, u8)]) -> Option<Self> {
        Self::from_byte_entries(pairs.iter().copied())
    }

    #[must_use]
    pub fn from_char_symbols(symbols: &[char]) -> Option<Self> {
        if symbols.len() != 64 {
            return None;
        }
        let mut map: BTreeMap<char, u8> = BTreeMap::new();
        for (value, symbol) in symbols.iter().copied().enumerate() {
            if symbol == '=' {
                return None;
            }
            if map.insert(symbol, value as u8).is_some() {
                return None;
            }
        }
        Some(Self {
            kind: CustomBase64AlphabetKind::OwnedCharacterMap(map),
        })
    }
}

impl<'a> CustomBase64Alphabet<'a> {
    #[must_use]
    pub fn from_character_map(map: &'a BTreeMap<char, u8>) -> Option<Self> {
        if map.is_empty()
            || map.len() > 64
            || map.contains_key(&'=')
            || map.values().any(|value: &u8| *value >= 64)
        {
            return None;
        }
        Some(Self {
            kind: CustomBase64AlphabetKind::BorrowedCharacterMap(map),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustomBase64Symbol {
    Value(u8),
    Padding,
    Ignored,
}

struct CustomBase64Decoder {
    policy: CustomBase64GroupPolicy,
    output: Vec<u8>,
    accumulator: u32,
    symbols: u32,
    padding: u32,
}

impl CustomBase64Decoder {
    fn new(policy: CustomBase64GroupPolicy, input_bytes: usize) -> Option<Self> {
        let complete_capacity: usize = (input_bytes / 4).checked_mul(3)?;
        let partial_capacity: usize = (input_bytes % 4).checked_mul(6)? / 8;
        let capacity: usize = complete_capacity.checked_add(partial_capacity)?;
        let mut output: Vec<u8> = Vec::new();
        output.try_reserve_exact(capacity).ok()?;
        Some(Self {
            policy,
            output,
            accumulator: 0,
            symbols: 0,
            padding: 0,
        })
    }

    fn push(&mut self, symbol: CustomBase64Symbol) -> Option<()> {
        match self.policy {
            CustomBase64GroupPolicy::KeepPartial => self.push_partial(symbol),
            CustomBase64GroupPolicy::DropPartial => self.push_group(symbol),
        }
    }

    fn push_partial(&mut self, symbol: CustomBase64Symbol) -> Option<()> {
        let CustomBase64Symbol::Value(value) = symbol else {
            return Some(());
        };
        self.accumulator = self.accumulator.checked_shl(6)? | u32::from(value);
        self.symbols += 6;
        if self.symbols >= 8 {
            self.symbols -= 8;
            self.output.push((self.accumulator >> self.symbols) as u8);
            self.accumulator &= (1u32 << self.symbols) - 1;
        }
        Some(())
    }

    fn push_group(&mut self, symbol: CustomBase64Symbol) -> Option<()> {
        match symbol {
            CustomBase64Symbol::Value(value) => {
                self.accumulator = self.accumulator.checked_shl(6)? | u32::from(value);
            }
            CustomBase64Symbol::Padding => {
                self.accumulator = self.accumulator.checked_shl(6)?;
                self.padding += 1;
            }
            CustomBase64Symbol::Ignored => return None,
        }
        self.symbols += 1;
        if self.symbols == 4 {
            self.output.push((self.accumulator >> 16) as u8);
            if self.padding < 2 {
                self.output.push((self.accumulator >> 8) as u8);
            }
            if self.padding < 1 {
                self.output.push(self.accumulator as u8);
            }
            self.accumulator = 0;
            self.symbols = 0;
            self.padding = 0;
        }
        Some(())
    }
}

fn byte_symbol(
    byte: u8,
    table: &[u8; 256],
    policy: CustomBase64GroupPolicy,
) -> Option<CustomBase64Symbol> {
    if byte == b'=' {
        return Some(CustomBase64Symbol::Padding);
    }
    if matches!(policy, CustomBase64GroupPolicy::KeepPartial) && matches!(byte, b'\n' | b'\r') {
        return Some(CustomBase64Symbol::Ignored);
    }
    let value: u8 = table[usize::from(byte)];
    (value != CUSTOM_BASE64_UNMAPPED).then_some(CustomBase64Symbol::Value(value))
}

fn character_symbol(
    character: char,
    map: &BTreeMap<char, u8>,
    policy: CustomBase64GroupPolicy,
) -> Option<CustomBase64Symbol> {
    if character == '=' {
        return Some(CustomBase64Symbol::Padding);
    }
    if let Some(value) = map.get(&character) {
        return Some(CustomBase64Symbol::Value(*value));
    }
    if matches!(policy, CustomBase64GroupPolicy::KeepPartial) && matches!(character, '\n' | '\r') {
        return Some(CustomBase64Symbol::Ignored);
    }
    None
}

#[must_use]
pub fn decode_custom_base64(
    input: CustomBase64Input<'_>,
    alphabet: &CustomBase64Alphabet<'_>,
    policy: CustomBase64GroupPolicy,
) -> Option<Vec<u8>> {
    let input_bytes: usize = match input {
        CustomBase64Input::Bytes(bytes) => bytes.len(),
        CustomBase64Input::Text(text) => text.len(),
    };
    let mut decoder: CustomBase64Decoder = CustomBase64Decoder::new(policy, input_bytes)?;
    match (&alphabet.kind, input) {
        (CustomBase64AlphabetKind::ByteTable(table), CustomBase64Input::Bytes(bytes)) => {
            for byte in bytes.iter().copied() {
                decoder.push(byte_symbol(byte, table, policy)?)?;
            }
        }
        (CustomBase64AlphabetKind::ByteTable(table), CustomBase64Input::Text(text)) => {
            for byte in text.bytes() {
                decoder.push(byte_symbol(byte, table, policy)?)?;
            }
        }
        (CustomBase64AlphabetKind::BorrowedCharacterMap(map), CustomBase64Input::Text(text)) => {
            for character in text.chars() {
                decoder.push(character_symbol(character, map, policy)?)?;
            }
        }
        (CustomBase64AlphabetKind::OwnedCharacterMap(map), CustomBase64Input::Text(text)) => {
            for character in text.chars() {
                decoder.push(character_symbol(character, map, policy)?)?;
            }
        }
        (CustomBase64AlphabetKind::BorrowedCharacterMap(map), CustomBase64Input::Bytes(bytes)) => {
            let text: &str = std::str::from_utf8(bytes).ok()?;
            for character in text.chars() {
                decoder.push(character_symbol(character, map, policy)?)?;
            }
        }
        (CustomBase64AlphabetKind::OwnedCharacterMap(map), CustomBase64Input::Bytes(bytes)) => {
            let text: &str = std::str::from_utf8(bytes).ok()?;
            for character in text.chars() {
                decoder.push(character_symbol(character, map, policy)?)?;
            }
        }
    }
    Some(decoder.output)
}

pub fn decode_with_custom_b64(input: &[u8], symbols: &[u8; 64]) -> Option<Vec<u8>> {
    let alphabet: CustomBase64Alphabet<'static> =
        CustomBase64Alphabet::from_legacy_byte_symbols(symbols);
    decode_custom_base64(
        CustomBase64Input::Bytes(input),
        &alphabet,
        CustomBase64GroupPolicy::KeepPartial,
    )
}

#[must_use]
pub fn try_known_custom_b64(input: &[u8]) -> Vec<CustomB64Match> {
    let candidates: &[(&[u8; 64], &str)] = &[
        (DARKGATE_ALPHA_V1, "darkgate-v1"),
        (DARKGATE_ALPHA_V2, "darkgate-v2"),
    ];
    let mut out: Vec<CustomB64Match> = Vec::new();
    for &(alpha, label) in candidates {
        let Some(decoded): Option<Vec<u8>> = decode_with_custom_b64(input, alpha) else {
            continue;
        };
        if let Some(crib) = custom_b64_crib_sniff(&decoded) {
            out.push(CustomB64Match {
                alphabet_label: label,
                crib_name: crib,
                decoded,
            });
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn adler32_per_byte(seed: u32, bytes: &[u8]) -> u32 {
        const MODULUS: u32 = 65_521;
        let mut low: u32 = seed & 0xffff;
        let mut high: u32 = seed >> 16;
        for byte in bytes {
            low = (low + u32::from(*byte)) % MODULUS;
            high = (high + low) % MODULUS;
        }
        (high << 16) | low
    }

    #[test]
    fn adler32_matches_per_byte_reference_across_chunk_boundaries() {
        let mut bytes: Vec<u8> = Vec::with_capacity(100_000);
        let mut state: u32 = 0x9e37_79b9;
        for _ in 0..100_000usize {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bytes.push((state >> 24) as u8);
        }
        for length in [0usize, 1, 5_551, 5_552, 5_553, 11_104, 100_000] {
            let input: &[u8] = &bytes[..length];
            for seed in [1u32, 0x1234_5678, u32::MAX] {
                assert_eq!(adler32(seed, input), adler32_per_byte(seed, input));
            }
        }
    }

    #[test]
    fn adler32_seeded_restart_matches_one_shot() {
        let bytes: Vec<u8> = (0u8..=255).cycle().take(12_345).collect();
        let split: usize = 6_789;
        let prefix: u32 = adler32(1, &bytes[..split]);
        assert_eq!(adler32(prefix, &bytes[split..]), adler32(1, &bytes));
    }

    #[test]
    fn adler32_pins_vectors_and_out_of_range_seed_behavior() {
        assert_eq!(adler32(1, b""), 1);
        assert_eq!(adler32(1, b"a"), 0x0062_0062);
        assert_eq!(adler32(1, b"abc"), 0x024d_0127);
        assert_eq!(adler32(u32::MAX, b""), u32::MAX);
        assert_eq!(adler32(u32::MAX, b"a"), 0x007d_006f);
    }

    #[test]
    fn decode_dispatches_each_scheme() {
        let payload: &[u8] = b"https://example.com/path system process";
        let b58: String = alphabets::base58_encode(payload, Base58Variant::Bitcoin);
        assert_eq!(
            decode(b58.as_bytes(), Scheme::Base58Bitcoin).unwrap(),
            payload
        );

        let pct: String =
            web_escape::percent_encode(payload, web_escape::PercentEncodeSet::RFC3986);
        assert_eq!(decode(pct.as_bytes(), Scheme::PercentUrl).unwrap(), payload);
    }

    #[test]
    fn percent_scheme_is_lenient_and_preserves_literal_plus() {
        let encoded: &[u8] = b"https%3A%2F%2Fexample.com%2G?q=a+b";
        assert_eq!(
            decode(encoded, Scheme::PercentUrl).unwrap(),
            b"https://example.com%2G?q=a+b"
        );
    }

    #[test]
    fn cascade_recovers_base91_url() {
        let payload: &[u8] = b"https://malware.example.com/payload powershell download";
        let encoded: String = alphabets::base91_encode(payload);
        let hits: Vec<CascadeHit> = blind_cascade(encoded.as_bytes());
        let hit: &CascadeHit = hits
            .iter()
            .find(|h: &&CascadeHit| h.scheme == Scheme::Base91)
            .expect("base91 hit");
        assert_eq!(hit.decoded, payload);
        assert_eq!(hit.reason, ValidationReason::PrintableText);
    }

    #[test]
    fn cascade_recovers_ascii85_nested_zip() {
        let payload: &[u8] = b"PK\x03\x04nested archive content bytes here padding xyz";
        let encoded: String = framed::ascii85_encode(payload);
        let hits: Vec<CascadeHit> = blind_cascade(encoded.as_bytes());
        assert!(
            hits.iter().any(|h: &CascadeHit| h.scheme == Scheme::Ascii85
                && h.reason == ValidationReason::NestedMagic),
            "{hits:?}"
        );
    }

    #[test]
    fn cascade_recovers_percent_url() {
        let payload: &[u8] = b"https://evil.example.com/c2?token=abcd config import";
        let encoded: String =
            web_escape::percent_encode(payload, web_escape::PercentEncodeSet::RFC3986);
        let hits: Vec<CascadeHit> = blind_cascade(encoded.as_bytes());
        assert!(
            hits.iter()
                .any(|h: &CascadeHit| h.scheme == Scheme::PercentUrl && h.decoded == payload),
            "{hits:?}"
        );
    }

    #[test]
    fn cascade_rejects_random_noise() {
        let noise: Vec<u8> = (0u32..512)
            .map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let hits: Vec<CascadeHit> = blind_cascade(&noise);
        for hit in &hits {
            assert_ne!(
                hit.reason,
                ValidationReason::PrintableText,
                "noise produced a printable-text false positive via {:?}",
                hit.scheme
            );
        }
    }

    #[test]
    fn cascade_ignores_tiny_input() {
        assert!(blind_cascade(b"ab").is_empty());
    }

    #[test]
    fn scheme_labels_are_unique() {
        let mut labels: Vec<&str> = Scheme::all().iter().map(|s: &Scheme| s.label()).collect();
        labels.sort_unstable();
        let count: usize = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count);
    }

    #[test]
    fn darkgate_v1_custom_b64_round_trips_pe_header() {
        let mz_payload: &[u8] =
            b"MZ\x90\x00this is a fake PE header to test the darkgate custom b64";
        let mut encoded: String = String::new();
        let alpha: &[u8; 64] = DARKGATE_ALPHA_V1;
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in mz_payload {
            buf = (buf << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                encoded.push(alpha[((buf >> bits) & 0x3f) as usize] as char);
            }
        }
        if bits > 0 {
            encoded.push(alpha[((buf << (6 - bits)) & 0x3f) as usize] as char);
            encoded.push('=');
        }
        let hits: Vec<CustomB64Match> = try_known_custom_b64(encoded.as_bytes());
        assert!(!hits.is_empty(), "expected a darkgate-v1 hit");
        assert_eq!(hits[0].alphabet_label, "darkgate-v1");
        assert_eq!(hits[0].crib_name, "pe-mz");
        assert_eq!(&hits[0].decoded[..2], b"MZ");
    }

    #[test]
    fn custom_b64_decode_rejects_out_of_alphabet() {
        let result: Option<Vec<u8>> = decode_with_custom_b64(b"ABC!@#", DARKGATE_ALPHA_V1);
        assert!(result.is_none());
    }

    fn standard_custom_alphabet() -> CustomBase64Alphabet<'static> {
        CustomBase64Alphabet::from_byte_symbols(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        )
        .expect("unique alphabet")
    }

    #[test]
    fn strict_custom_base64_defines_partial_and_padding_groups() {
        let alphabet: CustomBase64Alphabet<'static> = standard_custom_alphabet();
        for input in ["T", "TW", "TWE"] {
            let decoded: Vec<u8> = decode_custom_base64(
                CustomBase64Input::Text(input),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            )
            .expect("mapped symbols");
            assert!(decoded.is_empty(), "incomplete group {input:?}");
        }
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text("TWE="),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            Some(b"Ma".to_vec())
        );
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text("AA=A"),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            Some(vec![0, 0])
        );
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text("AAAA===="),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            Some(vec![0, 0, 0, 0])
        );
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text("===="),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            Some(vec![0])
        );
    }

    #[test]
    fn strict_custom_base64_rejects_unmapped_whitespace() {
        let alphabet: CustomBase64Alphabet<'static> = standard_custom_alphabet();
        for input in ["TW\nE=", "TW\rE=", "TW E="] {
            assert_eq!(
                decode_custom_base64(
                    CustomBase64Input::Text(input),
                    &alphabet,
                    CustomBase64GroupPolicy::DropPartial,
                ),
                None
            );
        }
    }

    #[test]
    fn strict_custom_base64_accepts_partial_maps_and_mapped_whitespace() {
        let map: BTreeMap<char, u8> = [('A', 0), ('B', 1), (' ', 2), ('D', 3)]
            .into_iter()
            .collect();
        let alphabet: CustomBase64Alphabet<'_> =
            CustomBase64Alphabet::from_character_map(&map).expect("bounded map");
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text("AB D"),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            Some(vec![0, 16, 131])
        );
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text("ABCE"),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            None
        );
    }

    #[test]
    fn keep_partial_preserves_mapped_newline_and_carriage_return() {
        let map: BTreeMap<char, u8> = [('A', 0), ('\n', 63), ('\r', 1)].into_iter().collect();
        let alphabet: CustomBase64Alphabet<'_> =
            CustomBase64Alphabet::from_character_map(&map).expect("mapped whitespace alphabet");
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text("\nA"),
                &alphabet,
                CustomBase64GroupPolicy::KeepPartial,
            ),
            Some(vec![252])
        );
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text("\rA"),
                &alphabet,
                CustomBase64GroupPolicy::KeepPartial,
            ),
            Some(vec![4])
        );
    }

    #[test]
    fn strict_custom_base64_accepts_valid_partial_byte_pairs() {
        let pairs: [(u8, u8); 4] = [(b'T', 19), (b'W', 22), (b'E', 4), (b'F', 5)];
        let alphabet: CustomBase64Alphabet<'static> =
            CustomBase64Alphabet::from_byte_pairs(&pairs).expect("partial byte alphabet");
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Bytes(b"TWE="),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            Some(b"Ma".to_vec())
        );
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Bytes(b"TWG="),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            None
        );
    }

    #[test]
    fn partial_byte_pairs_reject_empty_duplicate_reserved_and_out_of_range_entries() {
        assert!(CustomBase64Alphabet::from_byte_pairs(&[]).is_none());
        assert!(CustomBase64Alphabet::from_byte_pairs(&[(b'A', 0), (b'A', 1)]).is_none());
        assert!(CustomBase64Alphabet::from_byte_pairs(&[(b'=', 0)]).is_none());
        assert!(CustomBase64Alphabet::from_byte_pairs(&[(b'A', 64)]).is_none());
    }

    #[test]
    fn custom_base64_partial_alphabets_bound_each_constructor_at_sixty_four_symbols() {
        let exact_byte_pairs: Vec<(u8, u8)> = (0u8..64)
            .map(|value: u8| (value.wrapping_add(65), value))
            .collect();
        let exact_byte_alphabet: Option<CustomBase64Alphabet<'static>> =
            CustomBase64Alphabet::from_byte_pairs(&exact_byte_pairs);
        assert!(exact_byte_alphabet.is_some());
        let mut oversized_byte_pairs: Vec<(u8, u8)> = exact_byte_pairs.clone();
        oversized_byte_pairs.push((129, 0));
        let oversized_byte_alphabet: Option<CustomBase64Alphabet<'static>> =
            CustomBase64Alphabet::from_byte_pairs(&oversized_byte_pairs);
        assert!(oversized_byte_alphabet.is_none());

        let symbols: Vec<char> = (0..65u32)
            .map(|offset: u32| char::from_u32(0x1000 + offset).expect("valid scalar"))
            .collect();
        let exact_char_alphabet: Option<CustomBase64Alphabet<'static>> =
            CustomBase64Alphabet::from_char_symbols(&symbols[..64]);
        assert!(exact_char_alphabet.is_some());
        let oversized_char_alphabet: Option<CustomBase64Alphabet<'static>> =
            CustomBase64Alphabet::from_char_symbols(&symbols);
        assert!(oversized_char_alphabet.is_none());

        let exact_map: BTreeMap<char, u8> = symbols[..64]
            .iter()
            .copied()
            .enumerate()
            .map(|(value, symbol): (usize, char)| (symbol, value as u8))
            .collect();
        let exact_map_alphabet: Option<CustomBase64Alphabet<'_>> =
            CustomBase64Alphabet::from_character_map(&exact_map);
        assert!(exact_map_alphabet.is_some());
        let mut oversized_map: BTreeMap<char, u8> = exact_map.clone();
        oversized_map.insert(symbols[64], 0);
        let oversized_map_alphabet: Option<CustomBase64Alphabet<'_>> =
            CustomBase64Alphabet::from_character_map(&oversized_map);
        assert!(oversized_map_alphabet.is_none());
    }

    #[test]
    fn custom_base64_alphabet_refuses_duplicate_symbols() {
        let mut bytes: [u8; 64] =
            *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        bytes[63] = bytes[0];
        assert!(CustomBase64Alphabet::from_byte_symbols(&bytes).is_none());

        let mut chars: Vec<char> = (0..64u32)
            .map(|offset: u32| char::from_u32(0x1000 + offset).expect("valid scalar"))
            .collect();
        chars[63] = chars[0];
        assert!(CustomBase64Alphabet::from_char_symbols(&chars).is_none());
    }

    #[test]
    fn custom_base64_alphabet_refuses_the_reserved_padding_symbol() {
        let mut bytes: [u8; 64] =
            *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        bytes[63] = b'=';
        assert!(CustomBase64Alphabet::from_byte_symbols(&bytes).is_none());

        let map: BTreeMap<char, u8> = [('=', 0), ('A', 1)].into_iter().collect();
        assert!(CustomBase64Alphabet::from_character_map(&map).is_none());
    }

    #[test]
    fn custom_base64_character_alphabet_decodes_multibyte_symbols() {
        let chars: Vec<char> = (0..64u32)
            .map(|offset: u32| char::from_u32(0x1f300 + offset).expect("valid scalar"))
            .collect();
        let alphabet: CustomBase64Alphabet<'static> =
            CustomBase64Alphabet::from_char_symbols(&chars).expect("unique alphabet");
        let encoded: String = [chars[19], chars[22], chars[5], chars[46]]
            .into_iter()
            .collect();
        assert_eq!(
            decode_custom_base64(
                CustomBase64Input::Text(&encoded),
                &alphabet,
                CustomBase64GroupPolicy::DropPartial,
            ),
            Some(b"Man".to_vec())
        );
    }

    #[test]
    fn custom_base64_random_inputs_and_alphabets_never_panic() {
        let standard: [u8; 64] =
            *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for length in 0..512usize {
            let mut symbols: [u8; 64] = standard;
            for index in (1..symbols.len()).rev() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                symbols.swap(index, (state as usize) % (index + 1));
            }
            let alphabet: CustomBase64Alphabet<'static> =
                CustomBase64Alphabet::from_byte_symbols(&symbols).expect("permutation");
            let input: Vec<u8> = (0..length)
                .map(|_: usize| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (state >> 56) as u8
                })
                .collect();
            for policy in [
                CustomBase64GroupPolicy::KeepPartial,
                CustomBase64GroupPolicy::DropPartial,
            ] {
                let _: Option<Vec<u8>> =
                    decode_custom_base64(CustomBase64Input::Bytes(&input), &alphabet, policy);
            }
        }
    }

    #[test]
    fn custom_base64_decodes_multimegabyte_input_with_linear_output() {
        let alphabet: CustomBase64Alphabet<'static> = standard_custom_alphabet();
        let input: Vec<u8> = vec![b'A'; 2 * 1_024 * 1_024];
        let decoded: Vec<u8> = decode_custom_base64(
            CustomBase64Input::Bytes(&input),
            &alphabet,
            CustomBase64GroupPolicy::DropPartial,
        )
        .expect("bounded decode");
        assert_eq!(decoded.len(), 3 * input.len() / 4);
        assert!(decoded.iter().all(|byte: &u8| *byte == 0));
    }

    #[test]
    fn keep_partial_matches_the_previous_byte_decoder() {
        fn reference(input: &[u8], symbols: &[u8; 64]) -> Option<Vec<u8>> {
            let mut table: [Option<u8>; 256] = [None; 256];
            for (value, symbol) in symbols.iter().copied().enumerate() {
                table[usize::from(symbol)] = Some(value as u8);
            }
            let mut output: Vec<u8> = Vec::new();
            let mut accumulator: u32 = 0;
            let mut bits: u32 = 0;
            for byte in input.iter().copied() {
                if matches!(byte, b'=' | b'\n' | b'\r') {
                    continue;
                }
                accumulator = (accumulator << 6) | u32::from(table[usize::from(byte)]?);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    output.push((accumulator >> bits) as u8);
                    accumulator &= (1u32 << bits) - 1;
                }
            }
            Some(output)
        }

        let mut state: u64 = 0xd1b5_4a32_d192_ed03;
        for case in 0..1_024usize {
            let mut symbols: [u8; 64] = [0; 64];
            for symbol in &mut symbols {
                state = state
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
                *symbol = (state >> 56) as u8;
            }
            if case % 3 == 0 {
                symbols[case % symbols.len()] = b'=';
            }
            if case % 5 == 0 {
                symbols[63] = symbols[0];
            }
            let length: usize = case % 257;
            let input: Vec<u8> = (0..length)
                .map(|_: usize| {
                    state = state
                        .wrapping_mul(2_862_933_555_777_941_757)
                        .wrapping_add(3_037_000_493);
                    match state as usize % 67 {
                        index @ 0..64 => symbols[index],
                        64 => b'=',
                        65 => b'\n',
                        _ => b'\r',
                    }
                })
                .collect();
            assert_eq!(
                decode_with_custom_b64(&input, &symbols),
                reference(&input, &symbols),
                "case {case}"
            );
        }
    }

    #[test]
    fn drop_partial_matches_the_previous_character_decoder() {
        fn reference(input: &str, alphabet: &BTreeMap<char, u8>) -> Option<Vec<u8>> {
            let mut output: Vec<u8> = Vec::new();
            let mut accumulator: u32 = 0;
            let mut count: u32 = 0;
            let mut padding: u32 = 0;
            for character in input.chars() {
                if character == '=' {
                    accumulator = accumulator.checked_shl(6)?;
                    padding += 1;
                } else {
                    accumulator =
                        accumulator.checked_shl(6)? | u32::from(*alphabet.get(&character)?);
                }
                count += 1;
                if count == 4 {
                    output.push((accumulator >> 16) as u8);
                    if padding < 2 {
                        output.push((accumulator >> 8) as u8);
                    }
                    if padding < 1 {
                        output.push(accumulator as u8);
                    }
                    accumulator = 0;
                    count = 0;
                    padding = 0;
                }
            }
            Some(output)
        }

        let characters: Vec<char> = (0..64u32)
            .map(|offset: u32| char::from_u32(0x1f300 + offset).expect("valid scalar"))
            .collect();
        let map: BTreeMap<char, u8> = characters
            .iter()
            .copied()
            .enumerate()
            .map(|(value, character): (usize, char)| (character, value as u8))
            .collect();
        let alphabet: CustomBase64Alphabet<'_> =
            CustomBase64Alphabet::from_character_map(&map).expect("unique alphabet");
        let choices: Vec<char> = characters.iter().copied().chain(['=']).collect();
        let mut state: u64 = 0xa076_1d64_78bd_642f;
        for length in 0..1_024usize {
            let input: String = (0..length)
                .map(|_: usize| {
                    state = state
                        .wrapping_mul(3_202_034_522_624_059_733)
                        .wrapping_add(1);
                    choices[(state as usize) % choices.len()]
                })
                .collect();
            assert_eq!(
                decode_custom_base64(
                    CustomBase64Input::Text(&input),
                    &alphabet,
                    CustomBase64GroupPolicy::DropPartial,
                ),
                reference(&input, &map)
            );
        }
    }

    #[test]
    fn cascade_or_wall_emits_crypto_wall_when_no_decode() {
        use ::base64::Engine as _;
        use ::base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let header: String = B64URL.encode(br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#);
        let token: String = format!("{header}.QUJD.REVG.R0hJ.SktM");
        let outcome: CascadeRecovery = cascade_or_wall(token.as_bytes());
        let CascadeRecovery::Walled(wall) = outcome else {
            panic!("expected a crypto wall, got {outcome:?}");
        };
        assert_eq!(wall.kind, crypto_wall::CryptoWallKind::RsaOaep);
        assert!(wall.runtime_key_absent);
    }

    #[test]
    fn cascade_or_wall_decodes_recoverable_blob() {
        let payload: &[u8] = b"https://malware.example.com/payload powershell download config";
        let encoded: String = alphabets::base91_encode(payload);
        let outcome: CascadeRecovery = cascade_or_wall(encoded.as_bytes());
        assert!(
            matches!(outcome, CascadeRecovery::Decoded(_)),
            "recoverable blob must decode, not wall: {outcome:?}"
        );
    }

    #[test]
    fn cascade_or_wall_yields_nothing_on_plain_noise() {
        let blob: &[u8] = b"the quick brown fox jumps over the lazy dog repeatedly today";
        assert_eq!(cascade_or_wall(blob), CascadeRecovery::Nothing);
    }
}
