use std::collections::BTreeMap;
use std::io::Read as _;

use super::app::{HttpMessage, http_messages};
use super::{CaptureError, CaptureLimits, HttpExchange};

const MAX_HAR_BYTES: usize = 512 * 1024 * 1024;
const MAX_SAZ_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

type SessionFiles = (Option<Vec<u8>>, Option<Vec<u8>>);

pub(super) fn looks_like_har(bytes: &[u8]) -> bool {
    let head: &[u8] = &bytes[..bytes.len().min(4096)];
    let text: String = String::from_utf8_lossy(head).into_owned();
    let trimmed: &str = text.trim_start_matches('\u{feff}').trim_start();
    trimmed.starts_with('{') && text.contains("\"log\"")
}

pub(super) fn looks_like_saz(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        && bytes
            .windows(5)
            .take(1 << 20)
            .any(|window: &[u8]| window == b"raw/0" || window == b"raw\\0")
}

pub(super) fn har(bytes: &[u8], limits: &CaptureLimits) -> Result<Vec<HttpExchange>, CaptureError> {
    if bytes.len() > MAX_HAR_BYTES {
        return Err(CaptureError::Malformed(format!(
            "HAR file is larger than {MAX_HAR_BYTES} bytes"
        )));
    }
    let text: &str = std::str::from_utf8(bytes)
        .map_err(|error| CaptureError::Malformed(format!("HAR is not UTF-8: {error}")))?;
    let document: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|error| CaptureError::Malformed(format!("HAR is not JSON: {error}")))?;
    let entries: &Vec<serde_json::Value> = document["log"]["entries"]
        .as_array()
        .ok_or_else(|| CaptureError::Malformed("HAR has no log.entries array".to_owned()))?;
    let mut out: Vec<HttpExchange> = Vec::new();
    for entry in entries.iter().take(limits.exchanges) {
        let request: &serde_json::Value = &entry["request"];
        let response: &serde_json::Value = &entry["response"];
        let url: String = request["url"].as_str().unwrap_or_default().to_owned();
        let host: Option<String> = url.split_once("://").map(|(_, rest): (&str, &str)| {
            rest.split(['/', '?', '#'])
                .next()
                .unwrap_or_default()
                .to_owned()
        });
        let content: &serde_json::Value = &response["content"];
        let body_text: Option<&str> = content["text"].as_str();
        let base64: bool = content["encoding"].as_str() == Some("base64");
        out.push(HttpExchange {
            client: entry["clientIPAddress"].as_str().map(str::to_owned),
            server: entry["serverIPAddress"].as_str().map(str::to_owned),
            method: request["method"].as_str().unwrap_or_default().to_owned(),
            target: url,
            host,
            status: response["status"]
                .as_u64()
                .and_then(|code: u64| u16::try_from(code).ok()),
            content_type: content["mimeType"].as_str().map(str::to_owned),
            request_body_bytes: request["postData"]["text"].as_str().map_or(0, str::len),
            response_body_bytes: match body_text {
                Some(text) if base64 => text.len() / 4 * 3,
                Some(text) => text.len(),
                None => content["size"]
                    .as_u64()
                    .map_or(0, |size: u64| usize::try_from(size).unwrap_or(usize::MAX)),
            },
            response_body_complete: body_text.is_some(),
        });
    }
    Ok(out)
}

pub(super) fn saz(bytes: &[u8], limits: &CaptureLimits) -> Result<Vec<HttpExchange>, CaptureError> {
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|error| {
            CaptureError::Malformed(format!("SAZ is not a readable zip archive: {error}"))
        })?;
    let mut sessions: BTreeMap<String, SessionFiles> = BTreeMap::new();
    for index in 0..archive.len().min(limits.exchanges.saturating_mul(3)) {
        let mut file: zip::read::ZipFile<'_> = archive
            .by_index(index)
            .map_err(|error| CaptureError::Malformed(format!("SAZ entry {index}: {error}")))?;
        let name: String = file.name().replace('\\', "/");
        let Some(stem) = name.strip_prefix("raw/") else {
            continue;
        };
        let (session, side): (&str, char) =
            match (stem.strip_suffix("_c.txt"), stem.strip_suffix("_s.txt")) {
                (Some(session), _) => (session, 'c'),
                (_, Some(session)) => (session, 's'),
                _ => continue,
            };
        let mut content: Vec<u8> = Vec::new();
        (&mut file)
            .take(MAX_SAZ_ENTRY_BYTES)
            .read_to_end(&mut content)
            .map_err(|error| CaptureError::Malformed(format!("SAZ entry {name}: {error}")))?;
        let slot: &mut SessionFiles = sessions.entry(session.to_owned()).or_default();
        if side == 'c' {
            slot.0 = Some(content);
        } else {
            slot.1 = Some(content);
        }
    }
    let mut out: Vec<HttpExchange> = Vec::new();
    for (request, response) in sessions.into_values() {
        let requests: Vec<HttpMessage> = request
            .as_deref()
            .map(|r: &[u8]| http_messages(r, false, &[]))
            .unwrap_or_default();
        let methods: Vec<String> = requests.iter().map(|m: &HttpMessage| method(m)).collect();
        let responses: Vec<HttpMessage> = response
            .as_deref()
            .map(|r: &[u8]| http_messages(r, true, &methods))
            .unwrap_or_default();
        if let Some(first) = requests.first() {
            out.push(super::exchange(None, None, first, responses.first()));
        }
    }
    Ok(out)
}

pub(super) fn method(message: &HttpMessage) -> String {
    message
        .start_line
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_owned()
}
