use serde::{Deserialize, Serialize};

const MAX_SCAN: usize = 1 << 20;
const JOSE_HEADER_DECODE_CAP: usize = 4096;
const FERNET_KEY_BYTES: usize = 32;
const FERNET_SIGNING_KEY_BYTES: usize = 16;
const FERNET_KEY_TOKEN_MIN: usize = 43;
const FERNET_KEY_TOKEN_MAX: usize = 44;
const FERNET_MAX_STATIC_KEYS: usize = 64;
const FERNET_OVERHEAD: usize = 1 + 8 + 16 + 32;
const FERNET_MIN_LEN: usize = FERNET_OVERHEAD + 16;
const FERNET_IV_OFFSET: usize = 1 + 8;
const FERNET_CIPHERTEXT_OFFSET: usize = FERNET_IV_OFFSET + 16;
const FERNET_TAG_BYTES: usize = 32;
const MAX_STATIC_PASSPHRASES: usize = 32;
const PASSPHRASE_MIN_BYTES: usize = 4;
const PASSPHRASE_MAX_BYTES: usize = 128;
const AGE_SCRYPT_SALT_BYTES: usize = 16;
const AGE_FILE_KEY_BYTES: usize = 16;
const AGE_STANZA_BODY_BYTES: usize = AGE_FILE_KEY_BYTES + 16;
const AGE_MAC_BYTES: usize = 32;
const AGE_WRAP_KEY_BYTES: usize = 32;
const AGE_MAX_SCRYPT_LOG_N: u8 = 18;
const AGE_MAX_SCRYPT_ATTEMPTS: usize = 4;
const PBES2_MAX_SALT_BYTES: usize = 128;
const PBES2_MAX_IV_BYTES: usize = 16;
const PBES2_MAX_ENCRYPTED_BYTES: usize = 1 << 20;
const PBES2_MAX_ITERATIONS: u32 = 1_000_000;
const PBES2_MAX_ATTEMPTS: usize = 16;
const PEM_MAX_BLOCK_BYTES: usize = 1 << 20;
const LEGACY_PEM_MAX_ATTEMPTS: usize = 16;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type FernetHmac = hmac::Hmac<sha2::Sha256>;
type AgeHmac = hmac::Hmac<sha2::Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoWallKind {
    AesGcm,
    ChaCha20Poly1305,
    AesCbcHmac,
    Luks1RawVolumeKey,
    RsaPkcs1V15,
    RsaOaep,
}

impl CryptoWallKind {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AesGcm => "aes-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::AesCbcHmac => "aes-cbc-hmac",
            Self::Luks1RawVolumeKey => "luks1-raw-volume-key",
            Self::RsaPkcs1V15 => "rsa-pkcs1v15",
            Self::RsaOaep => "rsa-oaep",
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_aead(self) -> bool {
        matches!(
            self,
            Self::AesGcm | Self::ChaCha20Poly1305 | Self::AesCbcHmac
        )
    }

    #[inline]
    #[must_use]
    pub const fn is_rsa(self) -> bool {
        matches!(self, Self::RsaPkcs1V15 | Self::RsaOaep)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoWall {
    pub kind: CryptoWallKind,
    pub offset: usize,
    pub evidence: String,
    pub runtime_key_absent: bool,
}

impl CryptoWall {
    const fn new(kind: CryptoWallKind, offset: usize, evidence: String) -> Self {
        Self {
            kind,
            offset,
            evidence,
            runtime_key_absent: true,
        }
    }
}

#[must_use]
pub fn classify(data: &[u8]) -> Option<CryptoWall> {
    let window: &[u8] = &data[..data.len().min(MAX_SCAN)];
    classify_jwe(window)
        .or_else(|| classify_age(window))
        .or_else(|| classify_pkcs8_encrypted(window))
        .or_else(|| classify_pem_encrypted(window))
        .or_else(|| classify_fernet(window))
        .or_else(|| classify_cms_rsa(window))
}

fn classify_jwe(data: &[u8]) -> Option<CryptoWall> {
    let text: &str = core::str::from_utf8(data).ok()?;
    if let Some(wall) = jwe_compact(text) {
        return Some(wall);
    }
    jwe_json(text)
}

fn jwe_compact(text: &str) -> Option<CryptoWall> {
    for (offset, candidate) in jose_candidates(text) {
        let segments: Vec<&str> = candidate.split('.').collect();
        if segments.len() != 5 {
            continue;
        }
        if segments[0].is_empty() || segments[3].is_empty() || segments[4].is_empty() {
            continue;
        }
        if !segments
            .iter()
            .all(|s: &&str| s.bytes().all(is_base64url_byte))
        {
            continue;
        }
        let Some(header): Option<String> = decode_jose_header(segments[0]) else {
            continue;
        };
        if let Some(wall) = jose_header_wall(&header, offset, "jwe-compact") {
            return Some(wall);
        }
    }
    None
}

fn jwe_json(text: &str) -> Option<CryptoWall> {
    let offset: usize = text.find("\"protected\"")?;
    if !text.contains("\"ciphertext\"") {
        return None;
    }
    let after: &str = text.get(offset..)?;
    let header_b64: &str = extract_json_string_value(after, "\"protected\"")?;
    let header: String = decode_jose_header(header_b64)?;
    jose_header_wall(&header, offset, "jwe-json")
}

fn jose_header_wall(header: &str, offset: usize, framing: &str) -> Option<CryptoWall> {
    let alg: Option<&str> = json_string_field(header, "alg");
    let enc: Option<&str> = json_string_field(header, "enc");
    if let Some(alg) = alg
        && let Some(kind) = rsa_alg_kind(alg)
    {
        return Some(CryptoWall::new(
            kind,
            offset,
            format!(
                "{framing} header alg={alg}; RSA-wrapped content key, private key runtime-only"
            ),
        ));
    }
    if let Some(enc) = enc
        && let Some(kind) = aead_enc_kind(enc)
    {
        let alg_note: &str = alg.unwrap_or("dir");
        return Some(CryptoWall::new(
            kind,
            offset,
            format!(
                "{framing} header enc={enc} alg={alg_note}; content-encryption key runtime-only"
            ),
        ));
    }
    None
}

fn rsa_alg_kind(alg: &str) -> Option<CryptoWallKind> {
    match alg {
        "RSA-OAEP" | "RSA-OAEP-256" | "RSA-OAEP-384" | "RSA-OAEP-512" => {
            Some(CryptoWallKind::RsaOaep)
        }
        "RSA1_5" => Some(CryptoWallKind::RsaPkcs1V15),
        _ => None,
    }
}

fn aead_enc_kind(enc: &str) -> Option<CryptoWallKind> {
    match enc {
        "A128GCM" | "A192GCM" | "A256GCM" => Some(CryptoWallKind::AesGcm),
        "C20P" | "XC20P" => Some(CryptoWallKind::ChaCha20Poly1305),
        "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" => Some(CryptoWallKind::AesCbcHmac),
        _ => None,
    }
}

fn jose_candidates(text: &str) -> Vec<(usize, &str)> {
    let mut out: Vec<(usize, &str)> = Vec::new();
    let bytes: &[u8] = text.as_bytes();
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i <= bytes.len() {
        let boundary: bool = i == bytes.len() || !is_jose_token_byte(bytes[i]);
        if boundary {
            if i > start && text.is_char_boundary(start) && text.is_char_boundary(i) {
                let token: &str = &text[start..i];
                if token.starts_with("eyJ") && token.matches('.').count() == 4 {
                    out.push((start, token));
                    if out.len() >= 64 {
                        break;
                    }
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    out
}

#[inline]
const fn is_jose_token_byte(b: u8) -> bool {
    is_base64url_byte(b) || b == b'.'
}

#[inline]
const fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=')
}

fn decode_jose_header(segment: &str) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    if segment.len() > JOSE_HEADER_DECODE_CAP {
        return None;
    }
    let trimmed: &str = segment.trim_end_matches('=');
    let bytes: Vec<u8> = B64URL.decode(trimmed).ok()?;
    let text: String = String::from_utf8(bytes).ok()?;
    if text.contains('{') && text.contains('}') {
        Some(text)
    } else {
        None
    }
}

fn json_string_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle: String = format!("\"{key}\"");
    extract_json_string_value(json, &needle)
}

fn extract_json_string_value<'a>(json: &'a str, key_quoted: &str) -> Option<&'a str> {
    let key_at: usize = json.find(key_quoted)?;
    let rest: &str = &json[key_at + key_quoted.len()..];
    let colon: usize = rest.find(':')?;
    let after_colon: &str = rest[colon + 1..].trim_start();
    let after_colon: &str = after_colon.strip_prefix('"')?;
    let end: usize = after_colon.find('"')?;
    Some(&after_colon[..end])
}

fn classify_age(data: &[u8]) -> Option<CryptoWall> {
    const MARKER: &[u8] = b"age-encryption.org/v1";
    let offset: usize = crate::byte_search::find(data, MARKER)?;
    let passphrases: Vec<Vec<u8>> = static_passphrase_candidates(data);
    if age_scrypt_static_passphrase_opens(&data[offset..], &passphrases) {
        return None;
    }
    let stanza: &str = if crate::byte_search::find(data, b"-> X25519").is_some() {
        "X25519 recipient stanza"
    } else if crate::byte_search::find(data, b"-> scrypt").is_some() {
        "scrypt passphrase stanza"
    } else {
        "v1 header"
    };
    Some(CryptoWall::new(
        CryptoWallKind::ChaCha20Poly1305,
        offset,
        format!("age {stanza}; ChaCha20-Poly1305 payload, file key runtime-only"),
    ))
}

fn classify_pem_encrypted(data: &[u8]) -> Option<CryptoWall> {
    let markers: &[(&[u8], CryptoWallKind, &str)] = &[
        (
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
            CryptoWallKind::RsaPkcs1V15,
            "PKCS#8 encrypted private key (PEM)",
        ),
        (
            b"Proc-Type: 4,ENCRYPTED",
            CryptoWallKind::RsaPkcs1V15,
            "PEM legacy DEK-encrypted private key",
        ),
    ];
    let passphrases: Vec<Vec<u8>> = static_passphrase_candidates(data);
    for (marker, kind, evidence) in markers {
        if let Some(offset) = crate::byte_search::find(data, marker) {
            if *marker == b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
                && pkcs8_pem_static_passphrase_opens(data, &passphrases)
            {
                return None;
            }
            if *marker == b"Proc-Type: 4,ENCRYPTED"
                && legacy_pem_static_passphrase_opens(data, &passphrases)
            {
                return None;
            }
            return Some(CryptoWall::new(
                *kind,
                offset,
                format!("{evidence}; passphrase runtime-only"),
            ));
        }
    }
    None
}

fn classify_pkcs8_encrypted(data: &[u8]) -> Option<CryptoWall> {
    const PBES2_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
    if data.first() != Some(&0x30) {
        return None;
    }
    let offset: usize = crate::byte_search::find(data, PBES2_OID)?;
    let passphrases: Vec<Vec<u8>> = static_passphrase_candidates(data);
    if pkcs8_der_static_passphrase_opens(data, &passphrases) {
        return None;
    }
    Some(CryptoWall::new(
        CryptoWallKind::AesCbcHmac,
        offset,
        "PKCS#8 EncryptedPrivateKeyInfo (PBES2 DER); passphrase runtime-only".to_owned(),
    ))
}

#[derive(Debug, Clone)]
struct AgeScryptHeader<'a> {
    mac_input: &'a [u8],
    salt: [u8; AGE_SCRYPT_SALT_BYTES],
    log_n: u8,
    body: [u8; AGE_STANZA_BODY_BYTES],
    mac: [u8; AGE_MAC_BYTES],
}

#[derive(Debug, Clone)]
struct Pbes2Envelope<'a> {
    params: Pbes2Params,
    encrypted: &'a [u8],
}

#[derive(Debug, Clone)]
struct Pbes2Params {
    salt: Vec<u8>,
    iterations: u32,
    prf: Pbkdf2Prf,
    cipher: CbcCipher,
    iv: [u8; PBES2_MAX_IV_BYTES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pbkdf2Prf {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CbcCipher {
    Aes128,
    Aes192,
    Aes256,
}

impl CbcCipher {
    const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DerCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DerCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn from_sequence(bytes: &'a [u8]) -> Option<Self> {
        let mut outer: Self = Self::new(bytes);
        let inner: &'a [u8] = outer.read_tlv(0x30)?;
        if !outer.is_finished() {
            return None;
        }
        Some(Self::new(inner))
    }

    const fn is_finished(self) -> bool {
        self.pos == self.bytes.len()
    }

    fn peek_tag(self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn read_sequence(&mut self) -> Option<Self> {
        let inner: &'a [u8] = self.read_tlv(0x30)?;
        Some(Self::new(inner))
    }

    fn read_oid(&mut self) -> Option<&'a [u8]> {
        self.read_tlv(0x06)
    }

    fn read_tlv(&mut self, tag: u8) -> Option<&'a [u8]> {
        let found: u8 = *self.bytes.get(self.pos)?;
        if found != tag {
            return None;
        }
        self.pos = self.pos.checked_add(1)?;
        let len: usize = self.read_len()?;
        let end: usize = self.pos.checked_add(len)?;
        let value: &'a [u8] = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(value)
    }

    fn read_len(&mut self) -> Option<usize> {
        let first: u8 = *self.bytes.get(self.pos)?;
        self.pos = self.pos.checked_add(1)?;
        if first & 0x80 == 0 {
            return Some(usize::from(first));
        }
        let count: usize = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut len: usize = 0;
        for _ in 0..count {
            let b: u8 = *self.bytes.get(self.pos)?;
            self.pos = self.pos.checked_add(1)?;
            len = len.checked_shl(8)?.checked_add(usize::from(b))?;
        }
        Some(len)
    }
}

fn static_passphrase_candidates(data: &[u8]) -> Vec<Vec<u8>> {
    const LABELS: &[&[u8]] = &[
        b"age_passphrase",
        b"age-passphrase",
        b"passphrase",
        b"password",
        b"pkcs8_pass",
        b"pkcs8-password",
        b"pem_pass",
        b"pem-password",
        b"openssl_pass",
        b"openssl-password",
        b"pw",
    ];
    let mut out: Vec<Vec<u8>> = Vec::new();
    for label in LABELS {
        push_label_passphrases(data, label, &mut out);
        if out.len() >= MAX_STATIC_PASSPHRASES {
            break;
        }
    }
    out
}

fn push_label_passphrases(data: &[u8], label: &[u8], out: &mut Vec<Vec<u8>>) {
    let mut search: usize = 0;
    while search < data.len() && out.len() < MAX_STATIC_PASSPHRASES {
        let Some(rel): Option<usize> = find_ascii_case_insensitive(&data[search..], label) else {
            break;
        };
        let label_at: usize = search + rel;
        let mut pos: usize = label_at + label.len();
        if data.get(pos) == Some(&b'"') || data.get(pos) == Some(&b'\'') {
            pos += 1;
        }
        pos = skip_ascii_space(data, pos);
        let Some(sep): Option<u8> = data.get(pos).copied() else {
            search = label_at + label.len();
            continue;
        };
        if !matches!(sep, b'=' | b':') {
            search = label_at + label.len();
            continue;
        }
        pos += 1;
        pos = skip_ascii_space(data, pos);
        if let Some(candidate) = read_passphrase_value(data, pos)
            && !out.iter().any(|known: &Vec<u8>| known == &candidate)
        {
            out.push(candidate);
        }
        search = label_at + label.len();
    }
}

fn skip_ascii_space(data: &[u8], mut pos: usize) -> usize {
    while let Some(b) = data.get(pos)
        && b.is_ascii_whitespace()
    {
        pos += 1;
    }
    pos
}

fn read_passphrase_value(data: &[u8], pos: usize) -> Option<Vec<u8>> {
    let first: u8 = *data.get(pos)?;
    let (start, end): (usize, usize) = if matches!(first, b'"' | b'\'') {
        let quote: u8 = first;
        let start: usize = pos + 1;
        let rel_end: usize = data.get(start..)?.iter().position(|b: &u8| *b == quote)?;
        (start, start + rel_end)
    } else {
        let start: usize = pos;
        let mut end: usize = start;
        while let Some(b) = data.get(end)
            && !b.is_ascii_whitespace()
            && !matches!(*b, b',' | b';' | b'}' | b']' | b'\0')
        {
            end += 1;
        }
        (start, end)
    };
    let value: &[u8] = data.get(start..end)?;
    if value.len() < PASSPHRASE_MIN_BYTES || value.len() > PASSPHRASE_MAX_BYTES {
        return None;
    }
    Some(value.to_vec())
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window: &[u8]| ascii_eq_ignore_case(window, needle))
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b): (&u8, &u8)| a.eq_ignore_ascii_case(b))
}

fn age_scrypt_static_passphrase_opens(data: &[u8], passphrases: &[Vec<u8>]) -> bool {
    if passphrases.is_empty() {
        return false;
    }
    let Some(header): Option<AgeScryptHeader<'_>> = parse_age_scrypt_header(data) else {
        return false;
    };
    if header.log_n > AGE_MAX_SCRYPT_LOG_N {
        return false;
    }
    passphrases
        .iter()
        .take(AGE_MAX_SCRYPT_ATTEMPTS)
        .any(|passphrase: &Vec<u8>| age_scrypt_passphrase_opens(&header, passphrase))
}

fn parse_age_scrypt_header(data: &[u8]) -> Option<AgeScryptHeader<'_>> {
    const VERSION: &[u8] = b"age-encryption.org/v1\n";
    if !data.starts_with(VERSION) {
        return None;
    }
    let mac_rel: usize = crate::byte_search::find(data, b"\n--- ")?;
    let mac_line_start: usize = mac_rel + 1;
    let mac_mark_end: usize = mac_line_start + 3;
    let mac_b64_start: usize = mac_line_start + 4;
    let mac_line_end: usize = mac_b64_start
        + data
            .get(mac_b64_start..)?
            .iter()
            .position(|b: &u8| *b == b'\n')?;
    let mac_b64: &str = core::str::from_utf8(data.get(mac_b64_start..mac_line_end)?).ok()?;
    let mac_vec: Vec<u8> = decode_base64_standard_no_pad(mac_b64, 64)?;
    let mac: [u8; AGE_MAC_BYTES] = mac_vec.try_into().ok()?;
    let stanza_text: &str = core::str::from_utf8(data.get(VERSION.len()..mac_line_start)?).ok()?;
    let mut idx: usize = 0;
    let lines: Vec<&str> = stanza_text.split('\n').collect();
    let mut stanza_count: usize = 0;
    let mut found: Option<AgeScryptHeader<'_>> = None;
    while idx < lines.len() {
        let line: &str = trim_line_cr(lines[idx]);
        idx += 1;
        if line.is_empty() {
            continue;
        }
        if !line.starts_with("-> ") {
            return None;
        }
        stanza_count += 1;
        let args: Vec<&str> = line[3..]
            .split(' ')
            .filter(|s: &&str| !s.is_empty())
            .collect();
        let mut body_b64: String = String::new();
        while idx < lines.len() {
            let body_line: &str = trim_line_cr(lines[idx]);
            idx += 1;
            body_b64.push_str(body_line);
            if body_line.len() < 64 {
                break;
            }
        }
        if args.len() == 3 && args[0] == "scrypt" {
            let salt_vec: Vec<u8> = decode_base64_standard_no_pad(args[1], 64)?;
            let salt: [u8; AGE_SCRYPT_SALT_BYTES] = salt_vec.try_into().ok()?;
            let log_n: u8 = parse_age_log_n(args[2])?;
            let body_vec: Vec<u8> = decode_base64_standard_no_pad(&body_b64, 128)?;
            let body: [u8; AGE_STANZA_BODY_BYTES] = body_vec.try_into().ok()?;
            found = Some(AgeScryptHeader {
                mac_input: data.get(..mac_mark_end)?,
                salt,
                log_n,
                body,
                mac,
            });
        }
    }
    if stanza_count == 1 { found } else { None }
}

fn trim_line_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

fn parse_age_log_n(text: &str) -> Option<u8> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u8>().ok()
}

fn age_scrypt_passphrase_opens(header: &AgeScryptHeader<'_>, passphrase: &[u8]) -> bool {
    use chacha20poly1305::aead::{Aead, KeyInit as _};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use hmac::Mac as _;
    let params: scrypt::Params = match scrypt::Params::new(header.log_n, 8, 1, AGE_WRAP_KEY_BYTES) {
        Ok(params) => params,
        Err(_) => return false,
    };
    let mut salt: Vec<u8> = b"age-encryption.org/v1/scrypt".to_vec();
    salt.extend_from_slice(&header.salt);
    let mut wrap_key: [u8; AGE_WRAP_KEY_BYTES] = [0u8; AGE_WRAP_KEY_BYTES];
    if scrypt::scrypt(passphrase, &salt, &params, &mut wrap_key).is_err() {
        return false;
    }
    let cipher: ChaCha20Poly1305 = match ChaCha20Poly1305::new_from_slice(&wrap_key) {
        Ok(cipher) => cipher,
        Err(_) => return false,
    };
    let nonce_bytes: [u8; 12] = [0u8; 12];
    let nonce: &Nonce = match <&Nonce>::try_from(&nonce_bytes[..]) {
        Ok(nonce) => nonce,
        Err(_) => return false,
    };
    let file_key_vec: Vec<u8> = match cipher.decrypt(nonce, header.body.as_ref()) {
        Ok(file_key) => file_key,
        Err(_) => return false,
    };
    let Ok(file_key): Result<[u8; AGE_FILE_KEY_BYTES], _> = file_key_vec.try_into() else {
        return false;
    };
    let Some(hmac_key): Option<[u8; AGE_MAC_BYTES]> = hkdf_sha256(&file_key, &[], b"header") else {
        return false;
    };
    let mut mac: AgeHmac = match AgeHmac::new_from_slice(&hmac_key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(header.mac_input);
    mac.verify_slice(&header.mac).is_ok()
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Option<[u8; AGE_MAC_BYTES]> {
    use hmac::Mac as _;
    let mut extract: AgeHmac = AgeHmac::new_from_slice(salt).ok()?;
    extract.update(ikm);
    let prk: hmac::digest::Output<AgeHmac> = extract.finalize().into_bytes();
    let mut expand: AgeHmac = AgeHmac::new_from_slice(&prk).ok()?;
    expand.update(info);
    expand.update(&[1u8]);
    let okm: hmac::digest::Output<AgeHmac> = expand.finalize().into_bytes();
    let mut out: [u8; AGE_MAC_BYTES] = [0u8; AGE_MAC_BYTES];
    out.copy_from_slice(&okm);
    Some(out)
}

fn pkcs8_der_static_passphrase_opens(data: &[u8], passphrases: &[Vec<u8>]) -> bool {
    if passphrases.is_empty() {
        return false;
    }
    let Some(envelope): Option<Pbes2Envelope<'_>> = parse_pbes2_encrypted_private_key(data) else {
        return false;
    };
    passphrases
        .iter()
        .take(PBES2_MAX_ATTEMPTS)
        .any(|passphrase: &Vec<u8>| pbes2_passphrase_opens(&envelope, passphrase))
}

fn parse_pbes2_encrypted_private_key(data: &[u8]) -> Option<Pbes2Envelope<'_>> {
    const PBES2_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
    let mut root: DerCursor<'_> = DerCursor::from_sequence(data)?;
    let mut alg: DerCursor<'_> = root.read_sequence()?;
    let oid: &[u8] = alg.read_oid()?;
    if oid != PBES2_OID {
        return None;
    }
    let params_cursor: DerCursor<'_> = alg.read_sequence()?;
    if !alg.is_finished() {
        return None;
    }
    let params: Pbes2Params = parse_pbes2_params(params_cursor)?;
    let encrypted: &[u8] = root.read_tlv(0x04)?;
    if encrypted.is_empty() || encrypted.len() > PBES2_MAX_ENCRYPTED_BYTES || !root.is_finished() {
        return None;
    }
    Some(Pbes2Envelope { params, encrypted })
}

fn parse_pbes2_params(mut params: DerCursor<'_>) -> Option<Pbes2Params> {
    let kdf: DerCursor<'_> = params.read_sequence()?;
    let enc: DerCursor<'_> = params.read_sequence()?;
    if !params.is_finished() {
        return None;
    }
    let (salt, iterations, key_len, prf): (Vec<u8>, u32, Option<usize>, Pbkdf2Prf) =
        parse_pbkdf2_params(kdf)?;
    let (cipher, iv): (CbcCipher, [u8; PBES2_MAX_IV_BYTES]) = parse_pbes2_cipher(enc)?;
    if salt.is_empty()
        || salt.len() > PBES2_MAX_SALT_BYTES
        || iterations == 0
        || iterations > PBES2_MAX_ITERATIONS
        || key_len.is_some_and(|len: usize| len != cipher.key_len())
    {
        return None;
    }
    Some(Pbes2Params {
        salt,
        iterations,
        prf,
        cipher,
        iv,
    })
}

fn parse_pbkdf2_params(mut kdf: DerCursor<'_>) -> Option<(Vec<u8>, u32, Option<usize>, Pbkdf2Prf)> {
    const PBKDF2_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
    let oid: &[u8] = kdf.read_oid()?;
    if oid != PBKDF2_OID {
        return None;
    }
    let mut params: DerCursor<'_> = kdf.read_sequence()?;
    if !kdf.is_finished() {
        return None;
    }
    let salt: Vec<u8> = params.read_tlv(0x04)?.to_vec();
    let iterations: u32 = der_integer_u32(params.read_tlv(0x02)?)?;
    let key_len: Option<usize> = if params.peek_tag() == Some(0x02) {
        Some(usize::try_from(der_integer_u32(params.read_tlv(0x02)?)?).ok()?)
    } else {
        None
    };
    let prf: Pbkdf2Prf = if params.peek_tag() == Some(0x30) {
        parse_pbkdf2_prf(params.read_sequence()?)?
    } else {
        Pbkdf2Prf::Sha1
    };
    if !params.is_finished() {
        return None;
    }
    Some((salt, iterations, key_len, prf))
}

fn parse_pbkdf2_prf(mut prf: DerCursor<'_>) -> Option<Pbkdf2Prf> {
    const HMAC_SHA1_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07];
    const HMAC_SHA256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
    const HMAC_SHA384_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a];
    const HMAC_SHA512_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b];
    let oid: &[u8] = prf.read_oid()?;
    let parsed: Pbkdf2Prf = match oid {
        HMAC_SHA1_OID => Pbkdf2Prf::Sha1,
        HMAC_SHA256_OID => Pbkdf2Prf::Sha256,
        HMAC_SHA384_OID => Pbkdf2Prf::Sha384,
        HMAC_SHA512_OID => Pbkdf2Prf::Sha512,
        _ => return None,
    };
    if prf.peek_tag() == Some(0x05) {
        let null_value: &[u8] = prf.read_tlv(0x05)?;
        if !null_value.is_empty() {
            return None;
        }
    }
    if !prf.is_finished() {
        return None;
    }
    Some(parsed)
}

fn parse_pbes2_cipher(mut enc: DerCursor<'_>) -> Option<(CbcCipher, [u8; PBES2_MAX_IV_BYTES])> {
    const AES128_CBC_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
    const AES192_CBC_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16];
    const AES256_CBC_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
    let oid: &[u8] = enc.read_oid()?;
    let cipher: CbcCipher = match oid {
        AES128_CBC_OID => CbcCipher::Aes128,
        AES192_CBC_OID => CbcCipher::Aes192,
        AES256_CBC_OID => CbcCipher::Aes256,
        _ => return None,
    };
    let iv_bytes: &[u8] = enc.read_tlv(0x04)?;
    let iv: [u8; PBES2_MAX_IV_BYTES] = iv_bytes.try_into().ok()?;
    if !enc.is_finished() {
        return None;
    }
    Some((cipher, iv))
}

fn der_integer_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 5 || bytes[0] & 0x80 != 0 {
        return None;
    }
    let mut value: u32 = 0;
    for b in bytes.iter().copied().skip_while(|b: &u8| *b == 0) {
        value = value.checked_shl(8)?.checked_add(u32::from(b))?;
    }
    Some(value)
}

fn pbes2_passphrase_opens(envelope: &Pbes2Envelope<'_>, passphrase: &[u8]) -> bool {
    let key_len: usize = envelope.params.cipher.key_len();
    let mut key: Vec<u8> = vec![0u8; key_len];
    match envelope.params.prf {
        Pbkdf2Prf::Sha1 => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            passphrase,
            &envelope.params.salt,
            envelope.params.iterations,
            &mut key,
        ),
        Pbkdf2Prf::Sha256 => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            passphrase,
            &envelope.params.salt,
            envelope.params.iterations,
            &mut key,
        ),
        Pbkdf2Prf::Sha384 => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(
            passphrase,
            &envelope.params.salt,
            envelope.params.iterations,
            &mut key,
        ),
        Pbkdf2Prf::Sha512 => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            passphrase,
            &envelope.params.salt,
            envelope.params.iterations,
            &mut key,
        ),
    }
    let Some(plain): Option<Vec<u8>> = decrypt_aes_cbc_pkcs7(
        envelope.params.cipher,
        &key,
        &envelope.params.iv,
        envelope.encrypted,
    ) else {
        return false;
    };
    der_private_key_info_like(&plain)
}

fn decrypt_aes_cbc_pkcs7(
    cipher: CbcCipher,
    key: &[u8],
    iv: &[u8; PBES2_MAX_IV_BYTES],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return None;
    }
    let mut buf: Vec<u8> = ciphertext.to_vec();
    let plain: &[u8] = match cipher {
        CbcCipher::Aes128 => Aes128CbcDec::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .ok()?,
        CbcCipher::Aes192 => Aes192CbcDec::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .ok()?,
        CbcCipher::Aes256 => Aes256CbcDec::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .ok()?,
    };
    Some(plain.to_vec())
}

fn der_private_key_info_like(data: &[u8]) -> bool {
    let Some(mut root): Option<DerCursor<'_>> = DerCursor::from_sequence(data) else {
        return false;
    };
    let Some(version): Option<&[u8]> = root.read_tlv(0x02) else {
        return false;
    };
    let Some(version_value): Option<u32> = der_integer_u32(version) else {
        return false;
    };
    if version_value > 1 {
        return false;
    }
    let Some(mut alg): Option<DerCursor<'_>> = root.read_sequence() else {
        return false;
    };
    if alg.read_oid().is_none() {
        return false;
    }
    let Some(private_key): Option<&[u8]> = root.read_tlv(0x04) else {
        return false;
    };
    !private_key.is_empty()
}

fn der_legacy_private_key_like(data: &[u8]) -> bool {
    let Some(mut root): Option<DerCursor<'_>> = DerCursor::from_sequence(data) else {
        return false;
    };
    let Some(version): Option<&[u8]> = root.read_tlv(0x02) else {
        return false;
    };
    if der_integer_u32(version).is_none() {
        return false;
    }
    let mut int_count: usize = 0;
    while root.peek_tag() == Some(0x02) {
        let Some(value): Option<&[u8]> = root.read_tlv(0x02) else {
            return false;
        };
        if value.is_empty() {
            return false;
        }
        int_count += 1;
        if int_count >= 2 {
            return true;
        }
    }
    false
}

fn pkcs8_pem_static_passphrase_opens(data: &[u8], passphrases: &[Vec<u8>]) -> bool {
    if passphrases.is_empty() {
        return false;
    }
    let Some(text): Option<&str> = core::str::from_utf8(data).ok() else {
        return false;
    };
    let mut search: usize = 0;
    while let Some(rel) = text[search..].find("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        let begin_at: usize = search + rel;
        let body_start: usize = begin_at + "-----BEGIN ENCRYPTED PRIVATE KEY-----".len();
        let Some(end_rel): Option<usize> =
            text[body_start..].find("-----END ENCRYPTED PRIVATE KEY-----")
        else {
            break;
        };
        let block: &str = &text[body_start..body_start + end_rel];
        if let Some(der) = decode_base64_mime(block, PEM_MAX_BLOCK_BYTES)
            && pkcs8_der_static_passphrase_opens(&der, passphrases)
        {
            return true;
        }
        search = body_start + end_rel + "-----END ENCRYPTED PRIVATE KEY-----".len();
    }
    false
}

fn legacy_pem_static_passphrase_opens(data: &[u8], passphrases: &[Vec<u8>]) -> bool {
    if passphrases.is_empty() {
        return false;
    }
    let Some(text): Option<&str> = core::str::from_utf8(data).ok() else {
        return false;
    };
    let mut search: usize = 0;
    while let Some(rel) = text[search..].find("Proc-Type: 4,ENCRYPTED") {
        let proc_at: usize = search + rel;
        let Some(dek_rel): Option<usize> = text[proc_at..].find("DEK-Info:") else {
            search = proc_at + 1;
            continue;
        };
        let dek_at: usize = proc_at + dek_rel;
        let dek_line_end: usize = text[dek_at..]
            .find('\n')
            .map_or(text.len(), |line_rel: usize| dek_at + line_rel);
        let dek_line: &str = trim_line_cr(&text[dek_at + "DEK-Info:".len()..dek_line_end]).trim();
        let Some((cipher_name, iv_hex)): Option<(&str, &str)> = dek_line.split_once(',') else {
            search = dek_line_end;
            continue;
        };
        let Some((cipher, iv)): Option<(CbcCipher, [u8; PBES2_MAX_IV_BYTES])> =
            legacy_pem_cipher_iv(cipher_name.trim(), iv_hex.trim())
        else {
            search = dek_line_end;
            continue;
        };
        let Some(body_start): Option<usize> = pem_body_start(text, dek_line_end) else {
            search = dek_line_end;
            continue;
        };
        let Some(end_rel): Option<usize> = text[body_start..].find("-----END ") else {
            search = body_start;
            continue;
        };
        let block: &str = &text[body_start..body_start + end_rel];
        if let Some(ciphertext) = decode_base64_mime(block, PEM_MAX_BLOCK_BYTES)
            && passphrases
                .iter()
                .take(LEGACY_PEM_MAX_ATTEMPTS)
                .any(|passphrase: &Vec<u8>| {
                    legacy_pem_passphrase_opens(cipher, &iv, &ciphertext, passphrase)
                })
        {
            return true;
        }
        search = body_start + end_rel;
    }
    false
}

fn pem_body_start(text: &str, after_dek_line: usize) -> Option<usize> {
    if let Some(rel) = text[after_dek_line..].find("\r\n\r\n") {
        return Some(after_dek_line + rel + 4);
    }
    text[after_dek_line..]
        .find("\n\n")
        .map(|rel: usize| after_dek_line + rel + 2)
}

fn legacy_pem_cipher_iv(
    cipher_name: &str,
    iv_hex: &str,
) -> Option<(CbcCipher, [u8; PBES2_MAX_IV_BYTES])> {
    let cipher: CbcCipher = match cipher_name {
        "AES-128-CBC" => CbcCipher::Aes128,
        "AES-192-CBC" => CbcCipher::Aes192,
        "AES-256-CBC" => CbcCipher::Aes256,
        _ => return None,
    };
    let iv_vec: Vec<u8> = decode_hex(iv_hex)?;
    let iv: [u8; PBES2_MAX_IV_BYTES] = iv_vec.try_into().ok()?;
    Some((cipher, iv))
}

fn legacy_pem_passphrase_opens(
    cipher: CbcCipher,
    iv: &[u8; PBES2_MAX_IV_BYTES],
    ciphertext: &[u8],
    passphrase: &[u8],
) -> bool {
    let Some(salt): Option<&[u8]> = iv.get(..8) else {
        return false;
    };
    let key: Vec<u8> = evp_bytes_to_key_md5(passphrase, salt, cipher.key_len());
    let Some(plain): Option<Vec<u8>> = decrypt_aes_cbc_pkcs7(cipher, &key, iv, ciphertext) else {
        return false;
    };
    der_legacy_private_key_like(&plain)
}

fn evp_bytes_to_key_md5(passphrase: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut input: Vec<u8> = Vec::with_capacity(prev.len() + passphrase.len() + salt.len());
        input.extend_from_slice(&prev);
        input.extend_from_slice(passphrase);
        input.extend_from_slice(salt);
        let digest: md5::Digest = md5::compute(&input);
        prev = digest.0.to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(text.len() / 2);
    let bytes: &[u8] = text.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let high: u8 = hex_nibble(bytes[i])?;
        let low: u8 = hex_nibble(bytes[i + 1])?;
        out.push((high << 4) | low);
        i += 2;
    }
    Some(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_base64_standard_no_pad(token: &str, cap: usize) -> Option<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    if token.len() > cap || token.contains('=') {
        return None;
    }
    STANDARD_NO_PAD.decode(token).ok()
}

fn decode_base64_mime(text: &str, cap: usize) -> Option<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    let mut cleaned: String = String::with_capacity(text.len().min(cap));
    for b in text.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
            return None;
        }
        cleaned.push(char::from(b));
        if cleaned.len() > cap {
            return None;
        }
    }
    STANDARD.decode(cleaned).ok()
}

fn classify_cms_rsa(data: &[u8]) -> Option<CryptoWall> {
    const RSAES_OAEP_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07];
    const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const ENVELOPED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03];
    if data.first() != Some(&0x30) {
        return None;
    }
    let enveloped: bool = crate::byte_search::find(data, ENVELOPED_DATA_OID).is_some();
    if let Some(offset) = crate::byte_search::find(data, RSAES_OAEP_OID) {
        let context: &str = if enveloped {
            "CMS EnvelopedData"
        } else {
            "DER"
        };
        return Some(CryptoWall::new(
            CryptoWallKind::RsaOaep,
            offset,
            format!("{context} rsaesOaep recipient; private key runtime-only"),
        ));
    }
    if enveloped && let Some(offset) = crate::byte_search::find(data, RSA_ENCRYPTION_OID) {
        return Some(CryptoWall::new(
            CryptoWallKind::RsaPkcs1V15,
            offset,
            "CMS EnvelopedData rsaEncryption recipient; private key runtime-only".to_owned(),
        ));
    }
    None
}

fn classify_fernet(data: &[u8]) -> Option<CryptoWall> {
    let text: &str = core::str::from_utf8(data).ok()?;
    let static_keys: Vec<[u8; FERNET_KEY_BYTES]> = fernet_static_key_candidates(text);
    for (offset, token) in fernet_candidates(text) {
        let Some(raw): Option<Vec<u8>> = decode_base64url(token) else {
            continue;
        };
        if raw.len() < FERNET_MIN_LEN || raw[0] != 0x80 {
            continue;
        }
        if !(raw.len() - FERNET_OVERHEAD).is_multiple_of(16) {
            continue;
        }
        if static_keys
            .iter()
            .any(|key: &[u8; FERNET_KEY_BYTES]| fernet_static_key_opens(&raw, key))
        {
            continue;
        }
        return Some(CryptoWall::new(
            CryptoWallKind::AesCbcHmac,
            offset,
            "Fernet token (0x80 | ts | iv | aes-128-cbc | hmac-sha256); key runtime-only"
                .to_owned(),
        ));
    }
    None
}

fn fernet_candidates(text: &str) -> Vec<(usize, &str)> {
    let mut out: Vec<(usize, &str)> = Vec::new();
    let bytes: &[u8] = text.as_bytes();
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i <= bytes.len() {
        let boundary: bool = i == bytes.len() || !is_base64url_byte(bytes[i]);
        if boundary {
            if i > start && text.is_char_boundary(start) && text.is_char_boundary(i) {
                let run: &str = &text[start..i];
                for (relative_offset, token) in base64url_run_fragments(run) {
                    if token.starts_with("gAAAAA") && token.len() >= 100 {
                        out.push((start + relative_offset, token));
                        if out.len() >= 64 {
                            break;
                        }
                    }
                }
                if out.len() >= 64 {
                    break;
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    out
}

fn fernet_static_key_candidates(text: &str) -> Vec<[u8; FERNET_KEY_BYTES]> {
    let mut out: Vec<[u8; FERNET_KEY_BYTES]> = Vec::new();
    let bytes: &[u8] = text.as_bytes();
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i <= bytes.len() {
        let boundary: bool = i == bytes.len() || !is_base64url_byte(bytes[i]);
        if boundary {
            if i > start && text.is_char_boundary(start) && text.is_char_boundary(i) {
                let run: &str = &text[start..i];
                for (_, token) in base64url_run_fragments(run) {
                    if token.len() >= FERNET_KEY_TOKEN_MIN
                        && token.len() <= FERNET_KEY_TOKEN_MAX
                        && token.bytes().all(is_base64url_byte)
                    {
                        let Some(key): Option<[u8; FERNET_KEY_BYTES]> =
                            decode_fernet_static_key(token)
                        else {
                            continue;
                        };
                        if !out
                            .iter()
                            .any(|known: &[u8; FERNET_KEY_BYTES]| known == &key)
                        {
                            out.push(key);
                            if out.len() >= FERNET_MAX_STATIC_KEYS {
                                break;
                            }
                        }
                    }
                }
                if out.len() >= FERNET_MAX_STATIC_KEYS {
                    break;
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    out
}

fn base64url_run_fragments(run: &str) -> Vec<(usize, &str)> {
    let mut out: Vec<(usize, &str)> = vec![(0, run)];
    let mut search_start: usize = 0;
    while let Some(eq_offset) = run[search_start..].find('=') {
        let value_start: usize = search_start + eq_offset + 1;
        if value_start < run.len() {
            out.push((value_start, &run[value_start..]));
        }
        search_start = value_start;
    }
    out
}

fn decode_fernet_static_key(token: &str) -> Option<[u8; FERNET_KEY_BYTES]> {
    let decoded: Vec<u8> = decode_base64url(token)?;
    if decoded.len() != FERNET_KEY_BYTES {
        return None;
    }
    let mut key: [u8; FERNET_KEY_BYTES] = [0u8; FERNET_KEY_BYTES];
    key.copy_from_slice(&decoded);
    Some(key)
}

fn fernet_static_key_opens(raw: &[u8], key: &[u8; FERNET_KEY_BYTES]) -> bool {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
    use hmac::Mac as _;
    if raw.len() < FERNET_MIN_LEN || raw[0] != 0x80 {
        return false;
    }
    let Some(tag_offset): Option<usize> = raw.len().checked_sub(FERNET_TAG_BYTES) else {
        return false;
    };
    if tag_offset <= FERNET_CIPHERTEXT_OFFSET {
        return false;
    }
    let ciphertext: &[u8] = &raw[FERNET_CIPHERTEXT_OFFSET..tag_offset];
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return false;
    }
    let signing_key: &[u8] = &key[..FERNET_SIGNING_KEY_BYTES];
    let encryption_key: &[u8] = &key[FERNET_SIGNING_KEY_BYTES..];
    let signed: &[u8] = &raw[..tag_offset];
    let tag: &[u8] = &raw[tag_offset..];
    let mut mac: FernetHmac = match FernetHmac::new_from_slice(signing_key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(signed);
    if mac.verify_slice(tag).is_err() {
        return false;
    }
    let iv: &[u8] = &raw[FERNET_IV_OFFSET..FERNET_CIPHERTEXT_OFFSET];
    let mut buf: Vec<u8> = ciphertext.to_vec();
    Aes128CbcDec::new_from_slices(encryption_key, iv)
        .ok()
        .and_then(|decryptor: Aes128CbcDec| {
            decryptor
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .ok()
                .map(|plain: &[u8]| !plain.is_empty())
        })
        .unwrap_or(false)
}

fn decode_base64url(token: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    if token.len() > JOSE_HEADER_DECODE_CAP {
        return None;
    }
    URL_SAFE
        .decode(token)
        .or_else(|_| URL_SAFE_NO_PAD.decode(token.trim_end_matches('=')))
        .or_else(|_| STANDARD.decode(token))
        .ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    fn jwe_compact_token(header_json: &str) -> String {
        let h: String = B64URL.encode(header_json.as_bytes());
        format!("{h}.QUJD.REVG.R0hJ.SktM")
    }

    #[test]
    fn jwe_rsa_oaep_aes_gcm_walls_as_rsa() {
        let token: String = jwe_compact_token(r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#);
        let wall: CryptoWall = classify(token.as_bytes()).expect("jwe wall");
        assert_eq!(wall.kind, CryptoWallKind::RsaOaep);
        assert!(wall.runtime_key_absent);
        assert!(wall.kind.is_rsa());
        assert!(wall.evidence.contains("RSA-OAEP"), "{}", wall.evidence);
    }

    #[test]
    fn jwe_dir_aes_gcm_walls_as_aead() {
        let token: String = jwe_compact_token(r#"{"alg":"dir","enc":"A128GCM"}"#);
        let wall: CryptoWall = classify(token.as_bytes()).expect("jwe wall");
        assert_eq!(wall.kind, CryptoWallKind::AesGcm);
        assert!(wall.kind.is_aead());
    }

    #[test]
    fn jwe_chacha_poly_walls_as_chacha() {
        let token: String = jwe_compact_token(r#"{"alg":"dir","enc":"XC20P"}"#);
        let wall: CryptoWall = classify(token.as_bytes()).expect("jwe wall");
        assert_eq!(wall.kind, CryptoWallKind::ChaCha20Poly1305);
    }

    #[test]
    fn jwe_rsa1_5_walls_as_pkcs1() {
        let token: String = jwe_compact_token(r#"{"alg":"RSA1_5","enc":"A256GCM"}"#);
        let wall: CryptoWall = classify(token.as_bytes()).expect("jwe wall");
        assert_eq!(wall.kind, CryptoWallKind::RsaPkcs1V15);
    }

    #[test]
    fn jwe_embedded_in_surrounding_text_carries_offset() {
        let token: String = jwe_compact_token(r#"{"alg":"RSA-OAEP-256","enc":"A256GCM"}"#);
        let blob: String = format!("Authorization: Bearer {token}\n");
        let wall: CryptoWall = classify(blob.as_bytes()).expect("jwe wall");
        assert_eq!(wall.kind, CryptoWallKind::RsaOaep);
        assert_eq!(wall.offset, blob.find("eyJ").expect("header start"));
    }

    #[test]
    fn jwe_json_serialization_walls() {
        let protected: String = B64URL.encode(br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#);
        let json: String = format!(
            "{{\"protected\":\"{protected}\",\"encrypted_key\":\"x\",\"iv\":\"y\",\"ciphertext\":\"z\",\"tag\":\"t\"}}"
        );
        let wall: CryptoWall = classify(json.as_bytes()).expect("jwe-json wall");
        assert_eq!(wall.kind, CryptoWallKind::RsaOaep);
        assert!(wall.evidence.contains("jwe-json"), "{}", wall.evidence);
    }

    #[test]
    fn age_header_walls_as_chacha() {
        let blob: &[u8] =
            b"age-encryption.org/v1\n-> X25519 abc\nkeybytes\n--- mac\n\x00\x01\x02binarypayload";
        let wall: CryptoWall = classify(blob).expect("age wall");
        assert_eq!(wall.kind, CryptoWallKind::ChaCha20Poly1305);
        assert!(wall.evidence.contains("X25519"), "{}", wall.evidence);
    }

    #[test]
    fn pem_encrypted_private_key_walls() {
        let blob: &[u8] = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB...\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let wall: CryptoWall = classify(blob).expect("pem wall");
        assert!(wall.kind.is_rsa());
        assert!(wall.evidence.contains("PKCS#8"), "{}", wall.evidence);
    }

    #[test]
    fn cms_enveloped_rsa_oaep_walls() {
        let mut der: Vec<u8> = vec![0x30, 0x82, 0x01, 0x00];
        der.extend_from_slice(&[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03,
        ]);
        der.extend_from_slice(&[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07,
        ]);
        der.resize(256, 0);
        let wall: CryptoWall = classify(&der).expect("cms wall");
        assert_eq!(wall.kind, CryptoWallKind::RsaOaep);
        assert!(wall.evidence.contains("EnvelopedData"), "{}", wall.evidence);
    }

    #[test]
    fn fernet_token_walls() {
        let mut raw: Vec<u8> = vec![0x80];
        raw.extend_from_slice(&[0u8; 8]);
        raw.extend_from_slice(&[1u8; 16]);
        raw.extend_from_slice(&[2u8; 32]);
        raw.extend_from_slice(&[3u8; 32]);
        let token: String = base64::engine::general_purpose::URL_SAFE.encode(&raw);
        assert!(token.starts_with("gAAAAA"), "{token}");
        let wall: CryptoWall = classify(token.as_bytes()).expect("fernet wall");
        assert_eq!(wall.kind, CryptoWallKind::AesCbcHmac);
    }

    #[test]
    fn fernet_static_key_candidate_prevents_runtime_key_wall() {
        let blob: String =
            format!("FERNET_KEY={FERNET_STATIC_KEY_VECTOR}\nTOKEN={FERNET_STATIC_TOKEN_VECTOR}\n");
        assert_eq!(classify(blob.as_bytes()), None);
    }

    #[test]
    fn fernet_wrong_static_key_still_walls() {
        let key: [u8; FERNET_KEY_BYTES] = core::array::from_fn(|i: usize| i as u8);
        let mut wrong_key: [u8; FERNET_KEY_BYTES] = key;
        wrong_key[0] ^= 0x55;
        let key_text: String = B64URL.encode(wrong_key);
        let blob: String = format!("FERNET_KEY={key_text}\nTOKEN={FERNET_STATIC_TOKEN_VECTOR}\n");
        let wall: CryptoWall = classify(blob.as_bytes()).expect("fernet wall");
        assert_eq!(wall.kind, CryptoWallKind::AesCbcHmac);
    }

    #[test]
    fn age_scrypt_static_passphrase_prevents_runtime_key_wall() {
        let age: String = age_scrypt_fixture(b"vector-age-pass");
        let blob: String = format!("age_passphrase=\"vector-age-pass\"\n{age}");
        assert_eq!(classify(blob.as_bytes()), None);
    }

    #[test]
    fn age_scrypt_wrong_passphrase_still_walls() {
        let age: String = age_scrypt_fixture(b"vector-age-pass");
        let blob: String = format!("age_passphrase=\"wrong-age-pass\"\n{age}");
        let wall: CryptoWall = classify(blob.as_bytes()).expect("age wall");
        assert_eq!(wall.kind, CryptoWallKind::ChaCha20Poly1305);
        assert!(wall.evidence.contains("scrypt"), "{}", wall.evidence);
    }

    #[test]
    fn openssl_pkcs8_pbes2_passphrase_prevents_wall() {
        let blob: String = format!("pkcs8_pass=\"vector-pbes2-pass\"\n{OPENSSL_PKCS8_PEM}");
        assert_eq!(classify(blob.as_bytes()), None);
    }

    #[test]
    fn openssl_pkcs8_wrong_passphrase_still_walls() {
        let blob: String = format!("pkcs8_pass=\"wrong-pbes2-pass\"\n{OPENSSL_PKCS8_PEM}");
        let wall: CryptoWall = classify(blob.as_bytes()).expect("pkcs8 wall");
        assert_eq!(wall.kind, CryptoWallKind::RsaPkcs1V15);
        assert!(wall.evidence.contains("PKCS#8"), "{}", wall.evidence);
    }

    #[test]
    fn openssl_legacy_pem_passphrase_prevents_wall() {
        let blob: String = format!("pem_pass=\"vector-legacy-pass\"\n{OPENSSL_LEGACY_PEM}");
        assert_eq!(classify(blob.as_bytes()), None);
    }

    #[test]
    fn openssl_legacy_pem_wrong_passphrase_still_walls() {
        let blob: String = format!("pem_pass=\"wrong-legacy-pass\"\n{OPENSSL_LEGACY_PEM}");
        let wall: CryptoWall = classify(blob.as_bytes()).expect("legacy pem wall");
        assert_eq!(wall.kind, CryptoWallKind::RsaPkcs1V15);
        assert!(wall.evidence.contains("legacy"), "{}", wall.evidence);
    }

    #[test]
    fn plaintext_does_not_wall() {
        let blob: &[u8] = b"https://example.com/path?token=abc and some prose with the word system";
        assert_eq!(classify(blob), None);
    }

    #[test]
    fn static_key_high_entropy_blob_does_not_wall() {
        let blob: Vec<u8> = (0u32..4096)
            .map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        assert_eq!(
            classify(&blob),
            None,
            "random ciphertext must not false-wall"
        );
    }

    #[test]
    fn plain_jwt_is_not_a_jwe_wall() {
        let header: String = B64URL.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let jwt: String = format!("{header}.eyJzdWIiOiIxMjM0In0.signaturehere");
        assert_eq!(
            classify(jwt.as_bytes()),
            None,
            "a 3-segment signed JWT is not encrypted"
        );
    }

    #[test]
    fn jose_header_without_known_alg_does_not_wall() {
        let token: String = jwe_compact_token(r#"{"alg":"ECDH-ES","enc":"A256CBC"}"#);
        assert_eq!(classify(token.as_bytes()), None);
    }

    const REAL_JWE_RSA_OAEP_A256GCM: &str = "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00ifQ.pwgzO0dh31vUautjeJaz5Tw_rLWAIfKimLENI_Z_bhXiHojs0v7RAXqciSwOwY97-V5-RyCTJc8XUrWXzXDiKN4xA2tNcRYtL8CjI-b5wEZdr0EYkPVIX90kPnxzLlJc1drTEOuhA6gAkaWCy4TYK9twKUxhKhCUhcsQDWOpcQNwbWL0Y7sYPDJILL9Z38eyhmHKFRL5wb8n9-HsnGXWoYjZykTCVB1ypi-Qv_5qt48VwQ-X20f0HmjEBa7s9radH3iDfDCcr_YLWfregPJMUIxe2N8-D_fyxuZ3i2aXoeZOPFarOpXnYvZN0C7SGN4OAzeo4VweDqh8Bsxa7dWoxQ.Hhm3lp5sQKq989G3.w51ANzgG32NMxu7kT3Ubl9qjtsXoh1V7sda6OxeOk3BWinFkncx7mYKxGALz20TF1tJUO8Iii8zF.uxmZrgqsNcBkmeWCBhEzag";
    const REAL_JWE_DIR_A128GCM: &str = "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMTI4R0NNIn0..76354yXLQV4e8sbd.zYklLnoHCwXnsyaNC0fVlrMJz_BLXhy--iU-m1oKcGA7O__E5AuNPP3N_Syl3KAEXFiyfPc00ifU.QWXpcbkAHIiq7lntSiwiVg";
    const REAL_JWE_DIR_CBC_HS512: &str = "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2Q0JDLUhTNTEyIn0..kPY7y4gyGkaxIlm3piZFoA.RwH6k-TcEJMyOhrUTABiVTD9eL-n74ZvfTQ6KSYC2QswNgqW6XpXAS9G6WmbI7VekqBbgqsXn6Wx0wyHBQia0Q._YuFVqMrbJuik5TZ1jstC-4I9C5i09BFG6IRQOXfuzk";
    const REAL_JWE_ECDH_ES_A256GCM: &str = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkpzT21nTndXSV9vWnR1UXpVMUtwbXp3Y1lrLVV3MTBFVHE3TzNCQ3JzRmsiLCJ5IjoiX1FSeU9kc3M0UXZweUtKc2RlSUlyOFlyeDllTU5KQnlSVG52ZGZRMHhiQSJ9fQ..HLs70CsrhOL7nl8C.8uKUM6Gg-0QYp7vljoq_CDjX3Ymyic1z6jPoVFBnF6876lFyNgJUGKlLuJdpCZz67nZXGgG3vyi1.jSxxN6L4AfWij0GS8KBLcQ";
    const REAL_FERNET: &str = "gAAAAABqPUa5azYdc6JqhFafZYLJFrZUl0mW9iMVCrCSquTi_Jzh31TMQB8uAnxf8s5CC9cIQOpYFupgHoFLIVlg5GwK7q0R_NQI8pLsC0sVva3O6uBcN5KAi5S0hhx00TBzF17E-ZYx3uym192TTjXY2bO05Ywj0Q==";
    const FERNET_STATIC_KEY_VECTOR: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const FERNET_STATIC_TOKEN_VECTOR: &str = "gAAAAAAAAAAAQkJCQkJCQkJCQkJCQkJCQjCE_J7roB75QpUlhCgubvzYnGYwCsEzqVdAW45FA8L8sVBiJkb4cbbkgwh8dRS3btP5tygH7rf5c1q19U-HyNM=";
    const OPENSSL_PKCS8_PEM: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBlK9qXW0cc1rtNpypk\nMH6IAgID6DAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQZkoeKCJfMdBXFP78\nlpY4SgRAe5Gsg/sZEWIIEyMmLEPbdCu1E8IRjykNtrI11FnjVcxpmzX+SuiIyQfh\n2Djx9gOytxCQmeVsJFicKVHe6BiMnw==\n-----END ENCRYPTED PRIVATE KEY-----\n";
    const OPENSSL_LEGACY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,8567862E80A9F82FB01887E9E0E9FD80\n\nvgkZyiIqE1udbJJxPhiplhg8f4EXTzP/J6fne1Zh4TyMMSIwvNT+Kocelx3dpQ9C\nqdo+AtmsJJhVo2u0lqeocjTCs+7qs/tj6FpDjVNES+8IguY+UYGVmrQykLAteKC+\nyQ+2FvnSbpIOZuIuDlPCZcrsXSOMlMhNndlXQPOZ2bjsjDDSm9CmRJvucgzUirMr\nPNmgvREnjIxbH8HpNMz+dNzGCD/aZqsm6EH5a1y1sjbWlfJuyhEdpqMrUaMMD79V\nI6HSeWOoxa8AB9Gx0PIhYhKiYEAUtozAsRB98P9iryz0SStVzuVH0k/IL1h4PfUA\nwflNXI1BQIeQ9420WawzfInJJ7jFR9ztOFeSWGC9DUqHI4NfJnt0S17CnqegEnwh\nMG5M2OtEnoTjH4uc9mLThSyxUy5dKBPcwSW2ZWiflukGUATyDPO/N44SBfV9FVT7\n-----END RSA PRIVATE KEY-----\n";

    fn age_scrypt_fixture(passphrase: &[u8]) -> String {
        use chacha20poly1305::aead::{Aead, KeyInit as _};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        use hmac::Mac as _;
        let salt: [u8; AGE_SCRYPT_SALT_BYTES] = *b"0123456789abcdef";
        let file_key: [u8; AGE_FILE_KEY_BYTES] = *b"fedcba9876543210";
        let log_n: u8 = 10;
        let params: scrypt::Params =
            scrypt::Params::new(log_n, 8, 1, AGE_WRAP_KEY_BYTES).expect("scrypt params");
        let mut scrypt_salt: Vec<u8> = b"age-encryption.org/v1/scrypt".to_vec();
        scrypt_salt.extend_from_slice(&salt);
        let mut wrap_key: [u8; AGE_WRAP_KEY_BYTES] = [0u8; AGE_WRAP_KEY_BYTES];
        scrypt::scrypt(passphrase, &scrypt_salt, &params, &mut wrap_key).expect("scrypt");
        let cipher: ChaCha20Poly1305 =
            ChaCha20Poly1305::new_from_slice(&wrap_key).expect("chacha key");
        let nonce_bytes: [u8; 12] = [0u8; 12];
        let nonce: &Nonce = <&Nonce>::try_from(&nonce_bytes[..]).expect("nonce");
        let body: Vec<u8> = cipher.encrypt(nonce, file_key.as_ref()).expect("encrypt");
        let salt_b64: String = base64::engine::general_purpose::STANDARD_NO_PAD.encode(salt);
        let body_b64: String = base64::engine::general_purpose::STANDARD_NO_PAD.encode(body);
        let mut mac_input: Vec<u8> =
            format!("age-encryption.org/v1\n-> scrypt {salt_b64} {log_n}\n{body_b64}\n---")
                .into_bytes();
        let hmac_key: [u8; AGE_MAC_BYTES] =
            hkdf_sha256(&file_key, &[], b"header").expect("header key");
        let mut mac: AgeHmac = AgeHmac::new_from_slice(&hmac_key).expect("hmac");
        mac.update(&mac_input);
        let tag: hmac::digest::Output<AgeHmac> = mac.finalize().into_bytes();
        let tag_b64: String = base64::engine::general_purpose::STANDARD_NO_PAD.encode(tag);
        mac_input.extend_from_slice(b" ");
        mac_input.extend_from_slice(tag_b64.as_bytes());
        mac_input.extend_from_slice(b"\n");
        String::from_utf8(mac_input).expect("age header utf8")
    }

    #[test]
    fn real_jwcrypto_and_cryptography_tokens_classify() {
        let cases: &[(&str, CryptoWallKind)] = &[
            (REAL_JWE_RSA_OAEP_A256GCM, CryptoWallKind::RsaOaep),
            (REAL_JWE_DIR_A128GCM, CryptoWallKind::AesGcm),
            (REAL_JWE_DIR_CBC_HS512, CryptoWallKind::AesCbcHmac),
            (REAL_JWE_ECDH_ES_A256GCM, CryptoWallKind::AesGcm),
            (REAL_FERNET, CryptoWallKind::AesCbcHmac),
        ];
        for (token, want) in cases {
            let wall: CryptoWall = classify(token.as_bytes())
                .unwrap_or_else(|| panic!("real token must wall: {token}"));
            assert_eq!(wall.kind, *want, "token {token}");
            assert!(wall.runtime_key_absent);
        }
    }
}
