use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub(super) struct ApiError {
    pub(super) code: StatusCode,
    pub(super) error_code: &'static str,
    pub(super) message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body: serde_json::Value = serde_json::json!({
            "error_code": self.error_code,
            "message": self.message,
        });
        (self.code, Json(body)).into_response()
    }
}

pub(super) fn decode_inline_bytes(bytes_b64: &str) -> Result<Vec<u8>, ApiError> {
    if bytes_b64.is_empty() {
        return Err(ApiError {
            code: StatusCode::BAD_REQUEST,
            error_code: "DR-CLI-0182",
            message: "`bytes_b64` is required & must be non-empty; disrobe serve never reads from disk based on client input".to_owned(),
        });
    }
    decode_base64(bytes_b64).map_err(|e| ApiError {
        code: StatusCode::BAD_REQUEST,
        error_code: "DR-CLI-0181",
        message: format!("bytes_b64 decode: {e}"),
    })
}

pub(super) fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.len() % 4 == 1 {
        return Err("invalid base64 length".to_owned());
    }
    let pad_start: usize = cleaned.find('=').unwrap_or(cleaned.len());
    let pad: usize = cleaned.len().saturating_sub(pad_start);
    if pad > 2 {
        return Err("too many padding chars".to_owned());
    }
    if pad > 0 {
        if !cleaned.len().is_multiple_of(4) {
            return Err("padded base64 length must be a multiple of four".to_owned());
        }
        if pad_start == 0 {
            return Err("padding without payload".to_owned());
        }
        if cleaned[pad_start..].chars().any(|c: char| c != '=') {
            return Err("padding must be at the end".to_owned());
        }
    }
    let data: &str = &cleaned[..pad_start];
    let capacity: usize = cleaned.len().saturating_mul(3) / 4;
    let mut out: Vec<u8> = Vec::with_capacity(capacity);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in data.chars() {
        let v: u32 = match c {
            'A'..='Z' => u32::from(c as u8 - b'A'),
            'a'..='z' => u32::from(c as u8 - b'a' + 26),
            '0'..='9' => u32::from(c as u8 - b'0' + 52),
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return Err(format!("invalid base64 char: {c:?}")),
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte: u8 = ((buf >> bits) & 0xFF) as u8;
            out.push(byte);
        }
    }
    Ok(out)
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(super) fn encode_base64(input: &[u8]) -> String {
    let mut out: String = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks: std::slice::ChunksExact<'_, u8> = input.chunks_exact(3);
    for chunk in chunks.by_ref() {
        let n: u32 = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[(n & 0x3F) as usize] as char);
    }
    let rem: &[u8] = chunks.remainder();
    match rem.len() {
        1 => {
            let n: u32 = u32::from(rem[0]) << 16;
            out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n: u32 = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

pub(super) fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(64);
    for b in bytes {
        let _: std::fmt::Result = write!(s, "{b:02x}");
    }
    s
}

pub(super) fn normalize_dr_code(raw: &str) -> String {
    let upper: String = raw.trim().to_ascii_uppercase();
    if upper.starts_with("DR-") {
        return upper;
    }
    format!("DR-{upper}")
}
