pub mod alphabets;
pub mod cipher;
pub mod crypto_wall;
pub mod framed;
pub mod web_escape;

use thiserror::Error;

pub use alphabets::Base58Variant;
pub use cipher::{StreamCipher, TeaVariant};
pub use crypto_wall::{CryptoWall, CryptoWallKind, classify as classify_crypto_wall};

const MIN_CASCADE_INPUT: usize = 8;
const VALIDATE_PRINTABLE_RATIO: f64 = 0.90;
const VALIDATE_MIN_WORD_HITS: usize = 1;

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
        Scheme::PercentUrl => web_escape::percent_decode(input),
        Scheme::HtmlEntity => decode_text(input, web_escape::html_entity_decode),
        Scheme::Punycode => decode_text(input, |s: &str| {
            web_escape::punycode_decode(s).map(String::into_bytes)
        }),
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

pub fn decode_with_custom_b64(input: &[u8], alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let mut table: [Option<u8>; 256] = [None; 256];
    for (i, &ch) in alphabet.iter().enumerate() {
        table[ch as usize] = Some(i as u8);
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 3 / 4 + 1);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &ch in input {
        if ch == b'=' || ch == b'\n' || ch == b'\r' {
            continue;
        }
        let val: u32 = table[ch as usize]? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
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

    #[test]
    fn decode_dispatches_each_scheme() {
        let payload: &[u8] = b"https://example.com/path system process";
        let b58: String = alphabets::base58_encode(payload, Base58Variant::Bitcoin);
        assert_eq!(
            decode(b58.as_bytes(), Scheme::Base58Bitcoin).unwrap(),
            payload
        );

        let pct: String = web_escape::percent_encode(payload);
        assert_eq!(decode(pct.as_bytes(), Scheme::PercentUrl).unwrap(), payload);
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
        let encoded: String = web_escape::percent_encode(payload);
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

    #[test]
    fn cascade_or_wall_emits_crypto_wall_when_no_decode() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
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
