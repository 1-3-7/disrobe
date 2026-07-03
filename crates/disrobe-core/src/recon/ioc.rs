use std::collections::BTreeSet;
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

pub const IOC_SCHEMA: &str = "disrobe.ioc/v0";

const MIN_BLOB_LEN: usize = 24;
const MAX_BLOB_DECODE: usize = 1 << 20;
const MAX_INDICATORS: usize = 100_000;
const REGEX_SIZE_LIMIT: usize = 32 << 20;

const MIN_CODEC_TOKEN: usize = 16;
const MAX_CODEC_TOKEN: usize = 1 << 20;
const CODEC_PRINTABLE_RATIO: f64 = 0.85;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Url,
    Domain,
    Ipv4,
    Ipv6,
    Email,
    WindowsPath,
    RegistryKey,
    UnixPath,
    BitcoinAddress,
    EthereumAddress,
    MoneroAddress,
    LitecoinAddress,
    TronAddress,
    CreditCard,
    MacAddress,
    Uuid,
    PdbPath,
    CryptoConstant,
}

impl IocKind {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Domain => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Email => "email",
            Self::WindowsPath => "windows_path",
            Self::RegistryKey => "registry_key",
            Self::UnixPath => "unix_path",
            Self::BitcoinAddress => "bitcoin_address",
            Self::EthereumAddress => "ethereum_address",
            Self::MoneroAddress => "monero_address",
            Self::LitecoinAddress => "litecoin_address",
            Self::TronAddress => "tron_address",
            Self::CreditCard => "credit_card",
            Self::MacAddress => "mac_address",
            Self::Uuid => "uuid",
            Self::PdbPath => "pdb_path",
            Self::CryptoConstant => "crypto_constant",
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_network(self) -> bool {
        matches!(
            self,
            Self::Url | Self::Domain | Self::Ipv4 | Self::Ipv6 | Self::Email
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Plain,
    Base64,
    Hex,
    Codec,
}

impl Encoding {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Base64 => "base64",
            Self::Hex => "hex",
            Self::Codec => "codec",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indicator {
    pub kind: IocKind,
    pub value: String,
    pub offset: usize,
    pub encoding: Encoding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocReport {
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub byte_len: usize,
    pub total: usize,
    pub indicators: Vec<Indicator>,
}

struct PatternRule {
    kind: IocKind,
    pattern: Regex,
}

#[allow(clippy::expect_used)]
fn compile(pat: &str) -> Regex {
    RegexBuilder::new(pat)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .expect("DR-IOC-0001: static IOC pattern must compile")
}

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(r#"(?i)\b(?:https?|ftp|ftps|smb|file)://[^\s'"<>()\[\]{}\x00-\x1f\x7f]{1,2048}"#)
});

static REGISTRY_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[\\A-Za-z0-9 ._\-]{1,512}",
    )
});

static WINPATH_RE: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"\b[A-Za-z]:\\(?:[^\\/:*?"<>|\x00-\x1f\x7f ]{1,128}\\?){1,32}"#));

static UNIXPATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?:^|[\s'"(=:])((?:/(?:bin|etc|usr|var|tmp|opt|home|root|lib|lib64|sbin|proc|sys|dev|mnt|srv)|/(?:Users|Library|System|Applications|private|Volumes))(?:/[^\s'"<>:()\[\]{}\x00-\x1f\x7f]{1,128}){1,16})"#,
    )
});

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}\b",
    )
});

static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?\.){1,8}(?:com|net|org|info|biz|io|co|ru|cn|de|uk|gov|edu|mil|top|xyz|site|online|club|dev|app|sh|gg|tk|me|ly|to|cc|ws|su|onion|pw|link|live|tech)\b",
    )
});

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
    )
});

static IPV6_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{1,4}:){1,7}:|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}",
    )
});

static BTC_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b")
});

static ETH_RE: LazyLock<Regex> = LazyLock::new(|| compile(r"\b0x[a-fA-F0-9]{40}\b"));

static XMR_RE: LazyLock<Regex> = LazyLock::new(|| compile(r"\b4[0-9AB][a-km-zA-HJ-NP-Z1-9]{93}\b"));

static LTC_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"\b(?:[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[ac-hj-np-z02-9]{11,71})\b")
});

static TRON_RE: LazyLock<Regex> = LazyLock::new(|| compile(r"\bT[a-km-zA-HJ-NP-Z1-9]{33}\b"));

static MAC_RE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b"));

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
});

static PDB_RE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?i)\b[A-Za-z]:\\[^\r\n]{0,200}?\.(?:pdb|natvis)\b"));

static CARGO_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"/(?:home|Users)/[^/\s]{1,64}/\.cargo/registry/[^\s'\x22]{1,200}"));

static CC_RE: LazyLock<Regex> = LazyLock::new(|| compile(r"\b\d(?:[ -]?\d){12,18}\b"));

static B64_BLOB_RE: LazyLock<Regex> = LazyLock::new(|| compile(r"[A-Za-z0-9+/]{24,}={0,2}"));

static HEX_BLOB_RE: LazyLock<Regex> = LazyLock::new(|| compile(r"(?i)\b(?:[0-9a-f]{2}){16,}\b"));

static SIMPLE_RULES: LazyLock<Vec<PatternRule>> = LazyLock::new(|| {
    vec![
        PatternRule {
            kind: IocKind::Url,
            pattern: URL_RE.clone(),
        },
        PatternRule {
            kind: IocKind::RegistryKey,
            pattern: REGISTRY_RE.clone(),
        },
        PatternRule {
            kind: IocKind::WindowsPath,
            pattern: WINPATH_RE.clone(),
        },
        PatternRule {
            kind: IocKind::Email,
            pattern: EMAIL_RE.clone(),
        },
        PatternRule {
            kind: IocKind::Ipv4,
            pattern: IPV4_RE.clone(),
        },
        PatternRule {
            kind: IocKind::BitcoinAddress,
            pattern: BTC_RE.clone(),
        },
        PatternRule {
            kind: IocKind::MoneroAddress,
            pattern: XMR_RE.clone(),
        },
        PatternRule {
            kind: IocKind::LitecoinAddress,
            pattern: LTC_RE.clone(),
        },
        PatternRule {
            kind: IocKind::MacAddress,
            pattern: MAC_RE.clone(),
        },
        PatternRule {
            kind: IocKind::Uuid,
            pattern: UUID_RE.clone(),
        },
        PatternRule {
            kind: IocKind::PdbPath,
            pattern: PDB_RE.clone(),
        },
    ]
});

#[derive(Debug, Clone, Copy)]
struct CryptoConstant {
    name: &'static str,
    bytes: &'static [u8],
}

static CRYPTO_CONSTANTS: &[CryptoConstant] = &[
    CryptoConstant {
        name: "aes-sbox",
        bytes: &[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ],
    },
    CryptoConstant {
        name: "aes-inv-sbox",
        bytes: &[
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
            0xd7, 0xfb,
        ],
    },
    CryptoConstant {
        name: "md5-init",
        bytes: &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    },
    CryptoConstant {
        name: "sha1-init",
        bytes: &[
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
            0x54, 0x76,
        ],
    },
    CryptoConstant {
        name: "sha256-init-h0",
        bytes: &[0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85],
    },
    CryptoConstant {
        name: "sha512-init-h0",
        bytes: &[0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08],
    },
    CryptoConstant {
        name: "chacha20-sigma",
        bytes: b"expand 32-byte k",
    },
    CryptoConstant {
        name: "chacha20-tau",
        bytes: b"expand 16-byte k",
    },
    CryptoConstant {
        name: "base64-std-alphabet",
        bytes: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    },
    CryptoConstant {
        name: "base64-url-alphabet",
        bytes: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    },
    CryptoConstant {
        name: "tea-delta",
        bytes: &[0x9e, 0x37, 0x79, 0xb9],
    },
    CryptoConstant {
        name: "tea-delta-le",
        bytes: &[0xb9, 0x79, 0x37, 0x9e],
    },
    CryptoConstant {
        name: "crc32-poly",
        bytes: &[0x20, 0x83, 0xb8, 0xed],
    },
    CryptoConstant {
        name: "mersenne-twister-matrix",
        bytes: &[0xdf, 0xb0, 0x08, 0x99],
    },
];

#[inline]
fn context_window(text: &str, start: usize, len: usize) -> Option<String> {
    let lo: usize = start.saturating_sub(16);
    let hi: usize = (start + len + 16).min(text.len());
    let slice: &str = text.get(lo..hi)?;
    let trimmed: String = slice
        .chars()
        .map(|c: char| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const KECCAK_RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

#[inline]
const fn lane(x: usize, y: usize) -> usize {
    x + 5 * y
}

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &KECCAK_ROUND_CONSTANTS {
        let mut c: [u64; 5] = [0u64; 5];
        for (x, slot) in c.iter_mut().enumerate() {
            *slot = state[lane(x, 0)]
                ^ state[lane(x, 1)]
                ^ state[lane(x, 2)]
                ^ state[lane(x, 3)]
                ^ state[lane(x, 4)];
        }
        let mut d: [u64; 5] = [0u64; 5];
        for (x, slot) in d.iter_mut().enumerate() {
            *slot = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[lane(x, y)] ^= d[x];
            }
        }
        let mut b: [u64; 25] = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let nx: usize = y;
                let ny: usize = (2 * x + 3 * y) % 5;
                b[lane(nx, ny)] = state[lane(x, y)].rotate_left(KECCAK_RHO[x][y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                state[lane(x, y)] =
                    b[lane(x, y)] ^ ((!b[lane((x + 1) % 5, y)]) & b[lane((x + 2) % 5, y)]);
            }
        }
        state[lane(0, 0)] ^= rc;
    }
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state: [u64; 25] = [0u64; 25];
    let mut buf: Vec<u8> = input.to_vec();
    buf.push(0x01);
    while !buf.len().is_multiple_of(RATE) {
        buf.push(0x00);
    }
    let last: usize = buf.len() - 1;
    buf[last] |= 0x80;
    for block in buf.chunks_exact(RATE) {
        for (i, word) in block.chunks_exact(8).enumerate() {
            let lane: u64 = u64::from_le_bytes(word.try_into().unwrap_or([0u8; 8]));
            state[i] ^= lane;
        }
        keccak_f1600(&mut state);
    }
    let mut out: [u8; 32] = [0u8; 32];
    for (i, lane) in state.iter().take(4).enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// Validates an Ethereum address: all-lowercase / all-uppercase hex is accepted
/// (no checksum present), mixed case must satisfy the EIP-55 keccak checksum.
/// This is the discriminator a plain `0x[0-9a-fA-F]{40}` match lacks.
fn eth_address_valid(address: &str) -> bool {
    let Some(hex): Option<&str> = address.strip_prefix("0x") else {
        return false;
    };
    if hex.len() != 40 || !hex.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        return false;
    }
    let has_upper: bool = hex.bytes().any(|b: u8| b.is_ascii_uppercase());
    let has_lower: bool = hex.bytes().any(|b: u8| b.is_ascii_lowercase());
    if !(has_upper && has_lower) {
        return true;
    }
    let lower: String = hex.to_ascii_lowercase();
    let hash: [u8; 32] = keccak256(lower.as_bytes());
    for (i, ch) in hex.bytes().enumerate() {
        if !ch.is_ascii_alphabetic() {
            continue;
        }
        let nibble: u8 = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        let expect_upper: bool = nibble >= 8;
        if ch.is_ascii_uppercase() != expect_upper {
            return false;
        }
    }
    true
}

fn luhn_valid(digits: &str) -> bool {
    let only: Vec<u8> = digits
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b: u8| b - b'0')
        .collect();
    if only.len() < 13 || only.len() > 19 {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &d) in only.iter().rev().enumerate() {
        let mut v: u32 = u32::from(d);
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut num: Vec<u8> = Vec::with_capacity(s.len());
    for ch in s.bytes() {
        let val: usize = BASE58_ALPHABET.iter().position(|&a: &u8| a == ch)?;
        let mut carry: usize = val;
        for byte in &mut num {
            carry += (*byte as usize) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for ch in s.bytes() {
        if ch == b'1' {
            num.push(0);
        } else {
            break;
        }
    }
    num.reverse();
    Some(num)
}

#[allow(clippy::unreadable_literal)]
fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg: Vec<u8> = input.to_vec();
    let bit_len: u64 = (input.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w: [u32; 64] = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap_or([0u8; 4]));
        }
        for i in 16..64 {
            let s0: u32 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1: u32 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v: [u32; 8] = h;
        for i in 0..64 {
            let s1: u32 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch: u32 = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1: u32 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0: u32 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj: u32 = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2: u32 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out: [u8; 32] = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Validates a base58check address (BTC legacy, LTC legacy, Tron): the trailing
/// four bytes are the first four bytes of double-SHA256 over the payload.
fn base58check_valid(address: &str) -> bool {
    let Some(decoded): Option<Vec<u8>> = base58_decode(address) else {
        return false;
    };
    if decoded.len() < 5 {
        return false;
    }
    let split: usize = decoded.len() - 4;
    let payload: &[u8] = &decoded[..split];
    let checksum: &[u8] = &decoded[split..];
    let hash: [u8; 32] = sha256(&sha256(payload));
    hash[..4] == *checksum
}

fn collect_validated(
    re: &Regex,
    kind: IocKind,
    valid: fn(&str) -> bool,
    text: &str,
    encoding: Encoding,
    base_offset: usize,
    out: &mut Vec<Indicator>,
) {
    for m in re.find_iter(text) {
        if out.len() >= MAX_INDICATORS {
            return;
        }
        let value: &str = m.as_str();
        if !valid(value) {
            continue;
        }
        out.push(Indicator {
            kind,
            value: value.to_owned(),
            offset: base_offset + m.start(),
            encoding,
            context: if matches!(encoding, Encoding::Plain) {
                context_window(text, m.start(), value.len())
            } else {
                None
            },
        });
    }
}

fn collect_simple(text: &str, encoding: Encoding, base_offset: usize, out: &mut Vec<Indicator>) {
    for rule in SIMPLE_RULES.iter() {
        for m in rule.pattern.find_iter(text) {
            if out.len() >= MAX_INDICATORS {
                return;
            }
            let value: &str = m.as_str();
            out.push(Indicator {
                kind: rule.kind,
                value: value.to_owned(),
                offset: base_offset + m.start(),
                encoding,
                context: if matches!(encoding, Encoding::Plain) {
                    context_window(text, m.start(), value.len())
                } else {
                    None
                },
            });
        }
    }
}

fn collect_ipv6(text: &str, encoding: Encoding, base_offset: usize, out: &mut Vec<Indicator>) {
    for m in IPV6_RE.find_iter(text) {
        if out.len() >= MAX_INDICATORS {
            return;
        }
        let value: &str = m.as_str();
        if value.matches(':').count() < 2 {
            continue;
        }
        out.push(Indicator {
            kind: IocKind::Ipv6,
            value: value.to_owned(),
            offset: base_offset + m.start(),
            encoding,
            context: None,
        });
    }
}

fn collect_unix_paths(
    text: &str,
    encoding: Encoding,
    base_offset: usize,
    out: &mut Vec<Indicator>,
) {
    for caps in UNIXPATH_RE.captures_iter(text) {
        if out.len() >= MAX_INDICATORS {
            return;
        }
        let Some(g): Option<regex::Match<'_>> = caps.get(1) else {
            continue;
        };
        out.push(Indicator {
            kind: IocKind::UnixPath,
            value: g.as_str().to_owned(),
            offset: base_offset + g.start(),
            encoding,
            context: None,
        });
    }
}

fn collect_domains(text: &str, encoding: Encoding, base_offset: usize, out: &mut Vec<Indicator>) {
    let enclosing: BTreeSet<&str> = URL_RE
        .find_iter(text)
        .chain(EMAIL_RE.find_iter(text))
        .map(|m| m.as_str())
        .collect();
    for m in DOMAIN_RE.find_iter(text) {
        if out.len() >= MAX_INDICATORS {
            return;
        }
        let value: &str = m.as_str();
        if enclosing.iter().any(|u: &&str| u.contains(value)) {
            continue;
        }
        out.push(Indicator {
            kind: IocKind::Domain,
            value: value.to_owned(),
            offset: base_offset + m.start(),
            encoding,
            context: None,
        });
    }
}

fn collect_crypto_constants(bytes: &[u8], out: &mut Vec<Indicator>) {
    for c in CRYPTO_CONSTANTS {
        if let Some(at) = crate::byte_search::find(bytes, c.bytes) {
            out.push(Indicator {
                kind: IocKind::CryptoConstant,
                value: c.name.to_owned(),
                offset: at,
                encoding: Encoding::Plain,
                context: None,
            });
        }
    }
}

fn scan_text_layer(text: &str, encoding: Encoding, base_offset: usize, out: &mut Vec<Indicator>) {
    collect_simple(text, encoding, base_offset, out);
    collect_ipv6(text, encoding, base_offset, out);
    collect_unix_paths(text, encoding, base_offset, out);
    collect_domains(text, encoding, base_offset, out);
    collect_validated(
        &ETH_RE,
        IocKind::EthereumAddress,
        eth_address_valid,
        text,
        encoding,
        base_offset,
        out,
    );
    collect_validated(
        &TRON_RE,
        IocKind::TronAddress,
        base58check_valid,
        text,
        encoding,
        base_offset,
        out,
    );
    collect_validated(
        &CC_RE,
        IocKind::CreditCard,
        luhn_valid,
        text,
        encoding,
        base_offset,
        out,
    );
    for m in CARGO_PATH_RE.find_iter(text) {
        if out.len() >= MAX_INDICATORS {
            break;
        }
        out.push(Indicator {
            kind: IocKind::PdbPath,
            value: m.as_str().to_owned(),
            offset: base_offset + m.start(),
            encoding,
            context: None,
        });
    }
}

fn decode_and_recurse(text: &str, out: &mut Vec<Indicator>) {
    for m in B64_BLOB_RE.find_iter(text) {
        if out.len() >= MAX_INDICATORS {
            return;
        }
        let blob: &str = m.as_str();
        if blob.len() < MIN_BLOB_LEN || blob.len() > MAX_BLOB_DECODE {
            continue;
        }
        let Ok(decoded): Result<Vec<u8>, _> = B64_STANDARD.decode(blob.trim_end_matches('='))
        else {
            continue;
        };
        if let Some(inner) = printable_utf8(&decoded) {
            scan_text_layer(&inner, Encoding::Base64, m.start(), out);
        }
    }
    for m in HEX_BLOB_RE.find_iter(text) {
        if out.len() >= MAX_INDICATORS {
            return;
        }
        let blob: &str = m.as_str();
        if blob.len() > MAX_BLOB_DECODE {
            continue;
        }
        let Some(decoded): Option<Vec<u8>> = decode_hex(blob) else {
            continue;
        };
        if let Some(inner) = printable_utf8(&decoded) {
            scan_text_layer(&inner, Encoding::Hex, m.start(), out);
        }
    }
    decode_codecs_and_recurse(text, out);
}

#[inline]
const fn is_codec_token_byte(b: u8) -> bool {
    matches!(b, 0x21..=0x7e)
}

fn decode_codecs_and_recurse(text: &str, out: &mut Vec<Indicator>) {
    let bytes: &[u8] = text.as_bytes();
    let n: usize = bytes.len();
    let mut i: usize = 0;
    while i < n {
        if out.len() >= MAX_INDICATORS {
            return;
        }
        if !is_codec_token_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start: usize = i;
        while i < n && is_codec_token_byte(bytes[i]) {
            i += 1;
        }
        let token: &[u8] = &bytes[start..i];
        if token.len() < MIN_CODEC_TOKEN || token.len() > MAX_CODEC_TOKEN {
            continue;
        }
        for &scheme in crate::codec::Scheme::all() {
            if out.len() >= MAX_INDICATORS {
                return;
            }
            let Ok(decoded): Result<Vec<u8>, _> = crate::codec::decode(token, scheme) else {
                continue;
            };
            if decoded.is_empty() || decoded.as_slice() == token || decoded.len() > MAX_BLOB_DECODE
            {
                continue;
            }
            let Some(inner): Option<String> = codec_printable(&decoded) else {
                continue;
            };
            scan_text_layer(&inner, Encoding::Codec, start, out);
        }
    }
}

fn codec_printable(bytes: &[u8]) -> Option<String> {
    let s: &str = core::str::from_utf8(bytes).ok()?;
    let total: usize = s.chars().count();
    if total == 0 {
        return None;
    }
    let printable: usize = s
        .chars()
        .filter(|c: &char| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    if (printable as f64 / total as f64) >= CODEC_PRINTABLE_RATIO {
        Some(s.to_owned())
    } else {
        None
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len() / 2);
    let mut i: usize = 0;
    while i < bytes.len() {
        let hi: u8 = hex_val(bytes[i])?;
        let lo: u8 = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

#[inline]
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn printable_utf8(bytes: &[u8]) -> Option<String> {
    let s: &str = core::str::from_utf8(bytes).ok()?;
    let printable: usize = s
        .chars()
        .filter(|c: &char| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    let total: usize = s.chars().count();
    if total == 0 {
        return None;
    }
    let ratio: f64 = printable as f64 / total as f64;
    if ratio >= 0.85 {
        Some(s.to_owned())
    } else {
        None
    }
}

fn dedup_and_sort(mut indicators: Vec<Indicator>) -> Vec<Indicator> {
    indicators.sort_by(|a: &Indicator, b: &Indicator| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| a.encoding.cmp(&b.encoding))
            .then_with(|| a.offset.cmp(&b.offset))
    });
    indicators.dedup_by(|a: &mut Indicator, b: &mut Indicator| {
        a.kind == b.kind && a.value == b.value && a.encoding == b.encoding
    });
    indicators.sort_by(|a: &Indicator, b: &Indicator| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.value.cmp(&b.value))
    });
    indicators
}

#[must_use]
pub fn extract(bytes: &[u8]) -> Vec<Indicator> {
    extract_with_extra(bytes, &[])
}

fn decode_utf16le_runs(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() / 2);
    let mut i: usize = 0;
    let limit: usize = bytes.len().saturating_sub(1);
    while i < limit {
        let lo: u8 = bytes[i];
        let hi: u8 = bytes[i + 1];
        if hi == 0x00 && matches!(lo, 0x09 | 0x0a | 0x0d | 0x20..=0x7e) {
            out.push(lo as char);
            i += 2;
        } else {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            i += 1;
        }
    }
    out
}

fn scan_wide(bytes: &[u8], out: &mut Vec<Indicator>) {
    if bytes.len() < 8 {
        return;
    }
    let decoded: String = decode_utf16le_runs(bytes);
    if decoded.trim().is_empty() {
        return;
    }
    scan_text_layer(&decoded, Encoding::Plain, 0, out);
    decode_and_recurse(&decoded, out);
}

#[must_use]
pub fn extract_with_extra(bytes: &[u8], extra_text: &[&str]) -> Vec<Indicator> {
    let mut out: Vec<Indicator> = Vec::new();
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
    scan_text_layer(&text, Encoding::Plain, 0, &mut out);
    collect_crypto_constants(bytes, &mut out);
    decode_and_recurse(&text, &mut out);
    scan_wide(bytes, &mut out);
    for (idx, extra) in extra_text.iter().enumerate() {
        if out.len() >= MAX_INDICATORS {
            break;
        }
        let synthetic_base: usize = bytes.len().saturating_add(idx);
        scan_text_layer(extra, Encoding::Plain, synthetic_base, &mut out);
        decode_and_recurse(extra, &mut out);
    }
    dedup_and_sort(out)
}

#[must_use]
pub fn report(bytes: &[u8], uri: Option<&str>) -> IocReport {
    report_with_extra(bytes, uri, &[])
}

#[must_use]
pub fn report_with_extra(bytes: &[u8], uri: Option<&str>, extra_text: &[&str]) -> IocReport {
    let indicators: Vec<Indicator> = extract_with_extra(bytes, extra_text);
    IocReport {
        schema: IOC_SCHEMA,
        uri: uri.map(str::to_owned),
        byte_len: bytes.len(),
        total: indicators.len(),
        indicators,
    }
}

#[must_use]
pub fn defang(value: &str, kind: IocKind) -> String {
    match kind {
        IocKind::Url => value
            .replacen("https://", "hxxps://", 1)
            .replacen("http://", "hxxp://", 1)
            .replacen("ftp://", "fxp://", 1)
            .replace('.', "[.]"),
        IocKind::Domain | IocKind::Email | IocKind::Ipv4 => value.replace('.', "[.]"),
        IocKind::Ipv6 => value.replace(':', "[:]"),
        _ => value.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn kinds_of(ind: &[Indicator], kind: IocKind) -> Vec<&str> {
        ind.iter()
            .filter(|i: &&Indicator| i.kind == kind)
            .map(|i: &Indicator| i.value.as_str())
            .collect()
    }

    #[test]
    fn extracts_url_ipv4_email_domain() {
        let input: &[u8] =
            b"connect http://evil.example.com/payload to 192.168.0.1 mail bob@corp.org now bad-host.ru";
        let ind: Vec<Indicator> = extract(input);
        assert!(
            kinds_of(&ind, IocKind::Url).contains(&"http://evil.example.com/payload"),
            "{ind:?}"
        );
        assert!(kinds_of(&ind, IocKind::Ipv4).contains(&"192.168.0.1"));
        assert!(kinds_of(&ind, IocKind::Email).contains(&"bob@corp.org"));
        assert!(kinds_of(&ind, IocKind::Domain).contains(&"bad-host.ru"));
    }

    #[test]
    fn domain_inside_url_not_double_counted() {
        let input: &[u8] = b"https://malware.example.com/x";
        let ind: Vec<Indicator> = extract(input);
        let domains: Vec<&str> = kinds_of(&ind, IocKind::Domain);
        assert!(
            !domains.contains(&"malware.example.com"),
            "domain duplicated from URL: {ind:?}"
        );
    }

    #[test]
    fn domain_inside_email_not_double_counted() {
        let ind: Vec<Indicator> = extract(b"contact bob@corp.example.org now");
        assert!(kinds_of(&ind, IocKind::Email).contains(&"bob@corp.example.org"));
        assert!(
            !kinds_of(&ind, IocKind::Domain).contains(&"corp.example.org"),
            "domain duplicated from email: {ind:?}"
        );
    }

    #[test]
    fn windows_path_stops_before_next_token() {
        let ind: Vec<Indicator> =
            extract(b"drops C:\\Windows\\Temp\\x.exe then HKLM\\Software\\Run\\P");
        let paths: Vec<&str> = kinds_of(&ind, IocKind::WindowsPath);
        assert!(
            paths.contains(&"C:\\Windows\\Temp\\x.exe"),
            "path over-captured: {paths:?}"
        );
    }

    #[test]
    fn extracts_windows_path_and_registry() {
        let input: &[u8] =
            b"drops C:\\Windows\\Temp\\evil.exe and sets HKLM\\Software\\Run\\Persist value";
        let ind: Vec<Indicator> = extract(input);
        assert!(
            kinds_of(&ind, IocKind::WindowsPath)
                .iter()
                .any(|p: &&str| p.contains("evil.exe")),
            "{ind:?}"
        );
        assert!(
            kinds_of(&ind, IocKind::RegistryKey)
                .iter()
                .any(|p: &&str| p.contains("Software")),
            "{ind:?}"
        );
    }

    #[test]
    fn extracts_unix_path() {
        let input: &[u8] = b"writes /etc/cron.d/backdoor and reads /usr/bin/python3";
        let ind: Vec<Indicator> = extract(input);
        let paths: Vec<&str> = kinds_of(&ind, IocKind::UnixPath);
        assert!(paths.contains(&"/etc/cron.d/backdoor"), "{paths:?}");
        assert!(paths.contains(&"/usr/bin/python3"), "{paths:?}");
    }

    #[test]
    fn extracts_wallets() {
        let input: &[u8] = b"btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa eth 0x52908400098527886E0F7030069857D2E4169EE7 done";
        let ind: Vec<Indicator> = extract(input);
        assert!(
            kinds_of(&ind, IocKind::BitcoinAddress).contains(&"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        );
        assert!(
            kinds_of(&ind, IocKind::EthereumAddress)
                .contains(&"0x52908400098527886E0F7030069857D2E4169EE7")
        );
    }

    #[test]
    fn detects_aes_sbox_constant() {
        let mut input: Vec<u8> = vec![0u8; 8];
        input.extend_from_slice(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ]);
        let ind: Vec<Indicator> = extract(&input);
        assert!(
            kinds_of(&ind, IocKind::CryptoConstant).contains(&"aes-sbox"),
            "{ind:?}"
        );
    }

    #[test]
    fn detects_chacha_sigma_constant() {
        let ind: Vec<Indicator> = extract(b"prefix expand 32-byte k suffix");
        assert!(kinds_of(&ind, IocKind::CryptoConstant).contains(&"chacha20-sigma"));
    }

    #[test]
    fn recurses_one_level_through_base64() {
        let inner: &str = "http://hidden.example.io/c2";
        let encoded: String = B64_STANDARD.encode(inner);
        let payload: String = format!("data = {encoded}");
        let ind: Vec<Indicator> = extract(payload.as_bytes());
        let urls: Vec<&Indicator> = ind
            .iter()
            .filter(|i: &&Indicator| i.kind == IocKind::Url && i.encoding == Encoding::Base64)
            .collect();
        assert!(
            urls.iter().any(|i: &&Indicator| i.value == inner),
            "decoded url not found: {ind:?}"
        );
    }

    #[test]
    fn recurses_one_level_through_hex() {
        const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
        let inner: &str = "really-evil-domain.top";
        let mut encoded: String = String::with_capacity(inner.len() * 2);
        for b in inner.bytes() {
            encoded.push(LOWER_HEX[(b >> 4) as usize] as char);
            encoded.push(LOWER_HEX[(b & 0x0f) as usize] as char);
        }
        let ind: Vec<Indicator> = extract(encoded.as_bytes());
        assert!(
            ind.iter().any(|i: &Indicator| i.kind == IocKind::Domain
                && i.encoding == Encoding::Hex
                && i.value == inner),
            "decoded domain not found: {ind:?}"
        );
    }

    #[test]
    fn url_stops_at_control_byte() {
        let mut input: Vec<u8> = b"http://c2.example.com/gate.php".to_vec();
        input.push(0);
        input.extend_from_slice(b"HKLM\\Software\\Run");
        let ind: Vec<Indicator> = extract(&input);
        let urls: Vec<&str> = kinds_of(&ind, IocKind::Url);
        assert!(
            urls.contains(&"http://c2.example.com/gate.php"),
            "url over-captured past NUL: {urls:?}"
        );
    }

    #[test]
    fn dedup_collapses_repeats() {
        let input: &[u8] = b"1.2.3.4 1.2.3.4 1.2.3.4";
        let ind: Vec<Indicator> = extract(input);
        let ipv4: Vec<&str> = kinds_of(&ind, IocKind::Ipv4);
        assert_eq!(ipv4.len(), 1, "{ind:?}");
    }

    #[test]
    fn defang_neutralizes_url_and_ipv4() {
        assert_eq!(
            defang("http://1.2.3.4/p", IocKind::Url),
            "hxxp://1[.]2[.]3[.]4/p"
        );
        assert_eq!(defang("8.8.8.8", IocKind::Ipv4), "8[.]8[.]8[.]8");
        assert_eq!(defang("::1", IocKind::Ipv6), "[:][:]1");
    }

    #[test]
    fn report_round_trips_json() {
        let report: IocReport = report(b"hit http://x.example.com/", Some("a.bin"));
        let value: serde_json::Value = serde_json::to_value(&report).expect("serialize");
        assert_eq!(value["schema"], serde_json::json!(IOC_SCHEMA));
        assert_eq!(value["uri"], serde_json::json!("a.bin"));
        assert_eq!(value["total"], serde_json::json!(report.total));
        let back: Vec<Indicator> = serde_json::from_value(value["indicators"].clone())
            .expect("indicators round-trip back into typed vec");
        assert_eq!(back, report.indicators);
        assert!(report.total >= 1);
    }

    #[test]
    fn extra_text_is_scanned() {
        let ind: Vec<Indicator> = extract_with_extra(b"", &["reach 9.9.9.9 host"]);
        assert!(
            kinds_of(&ind, IocKind::Ipv4).contains(&"9.9.9.9"),
            "{ind:?}"
        );
    }

    #[test]
    fn no_indicators_on_clean_input() {
        let ind: Vec<Indicator> = extract(b"the quick brown fox jumps over thirteen lazy dogs");
        assert!(ind.is_empty(), "false positives: {ind:?}");
    }

    #[test]
    fn eip55_checksum_gates_ethereum_address() {
        let valid_mixed: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let ind: Vec<Indicator> = extract(format!("send to {valid_mixed} now").as_bytes());
        assert!(
            kinds_of(&ind, IocKind::EthereumAddress).contains(&valid_mixed),
            "valid EIP-55 address rejected: {ind:?}"
        );
        let mut wrong: String = valid_mixed.to_owned();
        wrong.replace_range(2..3, "A");
        let bad: Vec<Indicator> = extract(format!("send to {wrong} now").as_bytes());
        assert!(
            !kinds_of(&bad, IocKind::EthereumAddress).contains(&wrong.as_str()),
            "broken EIP-55 checksum must be rejected: {bad:?}"
        );
    }

    #[test]
    fn ethereum_all_one_case_is_accepted() {
        let lower: &str = "0x52908400098527886e0f7030069857d2e4169ee7";
        let ind: Vec<Indicator> = extract(format!("addr {lower}").as_bytes());
        assert!(kinds_of(&ind, IocKind::EthereumAddress).contains(&lower));
    }

    #[test]
    fn base58check_gates_tron_address() {
        let valid: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
        let ind: Vec<Indicator> = extract(format!("wallet {valid} pay").as_bytes());
        assert!(
            kinds_of(&ind, IocKind::TronAddress).contains(&valid),
            "valid base58check tron address rejected: {ind:?}"
        );
        let mut broken: String = valid.to_owned();
        broken.replace_range(33..34, "u");
        let bad: Vec<Indicator> = extract(format!("wallet {broken} pay").as_bytes());
        assert!(
            !kinds_of(&bad, IocKind::TronAddress).contains(&broken.as_str()),
            "broken checksum must be rejected: {bad:?}"
        );
    }

    #[test]
    fn litecoin_address_detected() {
        let valid: &str = "LhK2kQwiaAvhjWY799cZvMyYwnQAcxkarr";
        let ind: Vec<Indicator> = extract(format!("ltc {valid}").as_bytes());
        assert!(kinds_of(&ind, IocKind::LitecoinAddress).contains(&valid));
    }

    #[test]
    fn credit_card_requires_luhn() {
        let valid_visa: &str = "4111111111111111";
        let ind: Vec<Indicator> = extract(format!("card {valid_visa} exp").as_bytes());
        assert!(
            kinds_of(&ind, IocKind::CreditCard).contains(&valid_visa),
            "luhn-valid card rejected: {ind:?}"
        );
        let bad: &str = "4111111111111112";
        let no: Vec<Indicator> = extract(format!("card {bad} exp").as_bytes());
        assert!(
            !kinds_of(&no, IocKind::CreditCard).contains(&bad),
            "luhn-invalid number must be rejected: {no:?}"
        );
    }

    #[test]
    fn mac_and_uuid_detected() {
        let ind: Vec<Indicator> =
            extract(b"nic 00:1a:2b:3c:4d:5e id 550e8400-e29b-41d4-a716-446655440000");
        assert!(kinds_of(&ind, IocKind::MacAddress).contains(&"00:1a:2b:3c:4d:5e"));
        assert!(kinds_of(&ind, IocKind::Uuid).contains(&"550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn pdb_build_path_detected() {
        let ind: Vec<Indicator> =
            extract(br"compiled at C:\Users\dev\proj\target\release\app.pdb done");
        assert!(
            kinds_of(&ind, IocKind::PdbPath)
                .iter()
                .any(|p: &&str| p.to_ascii_lowercase().ends_with(".pdb")),
            "{ind:?}"
        );
    }

    #[test]
    fn utf16le_wide_strings_are_decoded() {
        let mut wide: Vec<u8> = Vec::new();
        for b in b"http://wide.example.com/c2" {
            wide.push(*b);
            wide.push(0x00);
        }
        let ind: Vec<Indicator> = extract(&wide);
        assert!(
            kinds_of(&ind, IocKind::Url)
                .iter()
                .any(|u: &&str| u.contains("wide.example.com")),
            "utf-16le url not recovered: {ind:?}"
        );
    }

    #[test]
    fn no_wallet_false_positives_on_prose() {
        let ind: Vec<Indicator> = extract(
            b"the meeting is scheduled for tomorrow afternoon to discuss quarterly results",
        );
        assert!(
            kinds_of(&ind, IocKind::EthereumAddress).is_empty()
                && kinds_of(&ind, IocKind::BitcoinAddress).is_empty()
                && kinds_of(&ind, IocKind::CreditCard).is_empty(),
            "wallet/card false positives: {ind:?}"
        );
    }

    #[test]
    fn recovers_url_through_base91_codec_layer() {
        let inner: &str = "http://codec.hidden.example.io/c2";
        let encoded: String = crate::codec::alphabets::base91_encode(inner.as_bytes());
        let ind: Vec<Indicator> = extract(encoded.as_bytes());
        assert!(
            ind.iter().any(|i: &Indicator| i.kind == IocKind::Url
                && i.encoding == Encoding::Codec
                && i.value == inner),
            "base91-wrapped url not recovered through the codec layer: {ind:?}"
        );
    }

    #[test]
    fn recovers_ipv4_through_ascii85_codec_layer() {
        let inner: &str = "beacon to 198.51.100.42 host";
        let encoded: String = crate::codec::framed::ascii85_encode(inner.as_bytes());
        let ind: Vec<Indicator> = extract(encoded.as_bytes());
        assert!(
            kinds_of(&ind, IocKind::Ipv4).contains(&"198.51.100.42"),
            "ascii85-wrapped ipv4 not recovered: {ind:?}"
        );
    }

    #[test]
    fn random_graphic_bytes_do_not_falsely_decode_into_iocs() {
        let noise: Vec<u8> = (0u32..2048)
            .map(|i: u32| (i.wrapping_mul(2_246_822_519) >> 9) as u8)
            .filter(u8::is_ascii_graphic)
            .collect();
        let ind: Vec<Indicator> = extract(&noise);
        assert!(
            ind.iter()
                .all(|i: &Indicator| i.kind != IocKind::Url && i.kind != IocKind::Email),
            "random bytes produced a spurious decoded url/email: {ind:?}"
        );
    }
}
