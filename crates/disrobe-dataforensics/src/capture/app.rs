use std::io::Read as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

const MAX_NAME_JUMPS: usize = 32;
const MAX_NAME_BYTES: usize = 255;
const MAX_DNS_RECORDS: usize = 256;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 256;
const MAX_MESSAGES_PER_STREAM: usize = 4096;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_CHUNKS: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn dns_name(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut at: usize = start;
    let mut end: Option<usize> = None;
    let mut jumps: usize = 0;
    let mut total: usize = 0;
    loop {
        let len: u8 = *message.get(at)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    return Some((labels.join("."), end.unwrap_or(at + 1)));
                }
                let label: &[u8] = message.get(at + 1..at + 1 + usize::from(len))?;
                total += label.len() + 1;
                if total > MAX_NAME_BYTES {
                    return None;
                }
                labels.push(String::from_utf8_lossy(label).into_owned());
                at += 1 + usize::from(len);
            }
            0xc0 => {
                jumps += 1;
                if jumps > MAX_NAME_JUMPS {
                    return None;
                }
                let pointer: usize = usize::from(be16(message, at)? & 0x3fff);
                end.get_or_insert(at + 2);
                at = pointer;
            }
            _ => return None,
        }
    }
}

pub(super) fn dns(message: &[u8]) -> Option<DnsMessage> {
    let id: u16 = be16(message, 0)?;
    let flags: u16 = be16(message, 2)?;
    let qd: usize = usize::from(be16(message, 4)?);
    let an: usize = usize::from(be16(message, 6)?);
    if qd > MAX_DNS_RECORDS || an > MAX_DNS_RECORDS || flags & 0x7800 != 0 {
        return None;
    }
    let mut at: usize = 12;
    let mut questions: Vec<DnsQuestion> = Vec::with_capacity(qd);
    for _ in 0..qd {
        let (name, next): (String, usize) = dns_name(message, at)?;
        questions.push(DnsQuestion {
            name,
            qtype: be16(message, next)?,
        });
        at = next + 4;
    }
    let mut answers: Vec<DnsAnswer> = Vec::with_capacity(an);
    for _ in 0..an {
        let (name, next): (String, usize) = dns_name(message, at)?;
        let rtype: u16 = be16(message, next)?;
        let ttl: u32 = be32(message, next + 4)?;
        let rdlen: usize = usize::from(be16(message, next + 8)?);
        let rdata_at: usize = next + 10;
        let rdata: &[u8] = message.get(rdata_at..rdata_at + rdlen)?;
        let data: String = match rtype {
            1 if rdlen == 4 => Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?).to_string(),
            28 if rdlen == 16 => Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?).to_string(),
            2 | 5 | 12 => dns_name(message, rdata_at)?.0,
            15 => dns_name(message, rdata_at + 2)?.0,
            16 => {
                let mut texts: Vec<String> = Vec::new();
                let mut cursor: usize = 0;
                while cursor < rdata.len() {
                    let len: usize = usize::from(rdata[cursor]);
                    texts.push(
                        String::from_utf8_lossy(rdata.get(cursor + 1..cursor + 1 + len)?)
                            .into_owned(),
                    );
                    cursor += 1 + len;
                }
                texts.join("")
            }
            _ => rdata.iter().map(|b: &u8| format!("{b:02x}")).collect(),
        };
        answers.push(DnsAnswer {
            name,
            rtype,
            ttl,
            data,
        });
        at = rdata_at + rdlen;
    }
    Some(DnsMessage {
        id,
        response: flags & 0x8000 != 0,
        rcode: (flags & 0x000f) as u8,
        questions,
        answers,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientHello {
    pub legacy_version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub ja3: String,
    pub ja3_md5: String,
}

const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

fn join(values: &[u16]) -> String {
    values
        .iter()
        .filter(|value: &&u16| !is_grease(**value))
        .map(u16::to_string)
        .collect::<Vec<String>>()
        .join("-")
}

pub(super) fn client_hello(stream: &[u8]) -> Option<ClientHello> {
    if *stream.first()? != 22 || *stream.get(1)? != 3 {
        return None;
    }
    let record_len: usize = usize::from(be16(stream, 3)?);
    let record: &[u8] = stream.get(5..5 + record_len)?;
    if *record.first()? != 1 {
        return None;
    }
    let body_len: usize = (usize::from(*record.get(1)?) << 16) | usize::from(be16(record, 2)?);
    let body: &[u8] = record
        .get(4..4 + body_len)
        .unwrap_or(&record[4.min(record.len())..]);
    let legacy_version: u16 = be16(body, 0)?;
    let mut at: usize = 34;
    let session_len: usize = usize::from(*body.get(at)?);
    at += 1 + session_len;
    let suites_len: usize = usize::from(be16(body, at)?);
    let suites: Vec<u16> = body
        .get(at + 2..at + 2 + suites_len)?
        .chunks_exact(2)
        .map(|pair: &[u8]| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    at += 2 + suites_len;
    let compression_len: usize = usize::from(*body.get(at)?);
    at += 1 + compression_len;
    let mut extensions: Vec<u16> = Vec::new();
    let mut groups: Vec<u16> = Vec::new();
    let mut point_formats: Vec<u16> = Vec::new();
    let mut sni: Option<String> = None;
    let mut alpn: Vec<String> = Vec::new();
    let mut supported_versions: Vec<u16> = Vec::new();
    if let Some(total) = be16(body, at) {
        let end: usize = (at + 2 + usize::from(total)).min(body.len());
        at += 2;
        while at + 4 <= end {
            let kind: u16 = be16(body, at)?;
            let len: usize = usize::from(be16(body, at + 2)?);
            let data: &[u8] = body.get(at + 4..at + 4 + len)?;
            extensions.push(kind);
            match kind {
                0 => {
                    if data.get(2) == Some(&0) {
                        let name_len: usize = usize::from(be16(data, 3)?);
                        sni =
                            Some(String::from_utf8_lossy(data.get(5..5 + name_len)?).into_owned());
                    }
                }
                10 => {
                    groups = data
                        .get(2..)?
                        .chunks_exact(2)
                        .map(|pair: &[u8]| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect();
                }
                11 => {
                    point_formats = data.get(1..)?.iter().map(|b: &u8| u16::from(*b)).collect();
                }
                16 => {
                    let mut cursor: usize = 2;
                    while cursor < data.len() {
                        let proto_len: usize = usize::from(data[cursor]);
                        alpn.push(
                            String::from_utf8_lossy(data.get(cursor + 1..cursor + 1 + proto_len)?)
                                .into_owned(),
                        );
                        cursor += 1 + proto_len;
                    }
                }
                43 => {
                    supported_versions = data
                        .get(1..)?
                        .chunks_exact(2)
                        .map(|pair: &[u8]| u16::from_be_bytes([pair[0], pair[1]]))
                        .filter(|value: &u16| !is_grease(*value))
                        .collect();
                }
                _ => {}
            }
            at += 4 + len;
        }
    }
    let ja3: String = format!(
        "{},{},{},{},{}",
        legacy_version,
        join(&suites),
        join(&extensions),
        join(&groups),
        join(&point_formats)
    );
    let ja3_md5: String = format!("{:x}", md5::compute(ja3.as_bytes()));
    Some(ClientHello {
        legacy_version,
        sni,
        alpn,
        supported_versions,
        ja3,
        ja3_md5,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HttpMessage {
    pub(super) start_line: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
    pub(super) body_complete: bool,
}

impl HttpMessage {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _): &&(String, String)| key.eq_ignore_ascii_case(name))
            .map(|(_, value): &(String, String)| value.as_str())
    }
}

pub(super) fn looks_like_http_request(stream: &[u8]) -> bool {
    [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    ]
    .iter()
    .any(|method: &&str| stream.starts_with(method.as_bytes()))
}

pub(super) fn http_messages(
    stream: &[u8],
    response: bool,
    request_methods: &[String],
) -> Vec<HttpMessage> {
    let mut out: Vec<HttpMessage> = Vec::new();
    let mut at: usize = 0;
    while at < stream.len() && out.len() < MAX_MESSAGES_PER_STREAM {
        let window: &[u8] = &stream[at..stream.len().min(at + MAX_HEADER_BYTES)];
        let Some(head_end) = window.windows(4).position(|w: &[u8]| w == b"\r\n\r\n") else {
            break;
        };
        let head: String = String::from_utf8_lossy(&window[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let start_line: String = lines.next().unwrap_or_default().to_owned();
        let valid_start: bool = if response {
            start_line.starts_with("HTTP/1.")
        } else {
            looks_like_http_request(start_line.as_bytes())
        };
        if !valid_start {
            break;
        }
        let headers: Vec<(String, String)> = lines
            .take(MAX_HEADERS)
            .filter_map(|line: &str| line.split_once(':'))
            .map(|(key, value): (&str, &str)| (key.trim().to_owned(), value.trim().to_owned()))
            .collect();
        let mut message: HttpMessage = HttpMessage {
            start_line,
            headers,
            body: Vec::new(),
            body_complete: true,
        };
        let body_start: usize = at + head_end + 4;
        let status: Option<u16> = response.then(|| {
            message
                .start_line
                .split(' ')
                .nth(1)
                .and_then(|code: &str| code.parse::<u16>().ok())
                .unwrap_or(0)
        });
        let request_was_head: bool = response
            && request_methods
                .get(out.len())
                .is_some_and(|method: &String| method == "HEAD");
        let no_body: bool = request_was_head
            || status
                .is_some_and(|code: u16| (100..200).contains(&code) || code == 204 || code == 304);
        let chunked: bool = message
            .header("Transfer-Encoding")
            .is_some_and(|value: &str| value.to_ascii_lowercase().contains("chunked"));
        let consumed: usize = if no_body {
            0
        } else if chunked {
            let (body, consumed, complete): (Vec<u8>, usize, bool) = dechunk(&stream[body_start..]);
            message.body = body;
            message.body_complete = complete;
            consumed
        } else if let Some(length) = message
            .header("Content-Length")
            .and_then(|v: &str| v.parse::<usize>().ok())
        {
            let available: usize = stream.len() - body_start;
            let take: usize = length.min(available).min(MAX_BODY_BYTES);
            message.body = stream[body_start..body_start + take].to_vec();
            message.body_complete = take == length;
            take
        } else if response {
            let take: usize = (stream.len() - body_start).min(MAX_BODY_BYTES);
            message.body = stream[body_start..body_start + take].to_vec();
            take
        } else {
            0
        };
        at = body_start + consumed;
        out.push(message);
    }
    out
}

fn dechunk(data: &[u8]) -> (Vec<u8>, usize, bool) {
    let mut body: Vec<u8> = Vec::new();
    let mut at: usize = 0;
    for _ in 0..MAX_CHUNKS {
        let Some(line_end) = data
            .get(at..)
            .and_then(|rest: &[u8]| rest.windows(2).position(|w: &[u8]| w == b"\r\n"))
        else {
            return (body, at, false);
        };
        let size_text: String = String::from_utf8_lossy(&data[at..at + line_end]).into_owned();
        let size_field: &str = size_text.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size_field, 16) else {
            return (body, at, false);
        };
        at += line_end + 2;
        if size == 0 {
            let trailer_end: usize = data
                .get(at..)
                .and_then(|rest: &[u8]| rest.windows(2).position(|w: &[u8]| w == b"\r\n"))
                .map_or(data.len(), |end: usize| at + end + 2);
            return (body, trailer_end, true);
        }
        let Some(chunk) = data.get(at..at + size) else {
            body.extend_from_slice(&data[at.min(data.len())..]);
            return (body, data.len(), false);
        };
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return (body, at, false);
        }
        body.extend_from_slice(chunk);
        at += size + 2;
    }
    (body, at, false)
}

pub(super) fn decoded_body(message: &HttpMessage) -> Option<Vec<u8>> {
    let encoding: String = message.header("Content-Encoding")?.to_ascii_lowercase();
    let mut out: Vec<u8> = Vec::new();
    let limit: u64 = MAX_BODY_BYTES as u64 + 1;
    let result: std::io::Result<usize> = match encoding.as_str() {
        "gzip" | "x-gzip" => flate2::read::GzDecoder::new(message.body.as_slice())
            .take(limit)
            .read_to_end(&mut out),
        "deflate" => {
            let zlib: std::io::Result<usize> =
                flate2::read::ZlibDecoder::new(message.body.as_slice())
                    .take(limit)
                    .read_to_end(&mut out);
            if zlib.is_ok() {
                zlib
            } else {
                out.clear();
                flate2::read::DeflateDecoder::new(message.body.as_slice())
                    .take(limit)
                    .read_to_end(&mut out)
            }
        }
        "br" => brotli::Decompressor::new(message.body.as_slice(), 4096)
            .take(limit)
            .read_to_end(&mut out),
        _ => return None,
    };
    (result.is_ok() && out.len() <= MAX_BODY_BYTES).then_some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn compressed_dns_names_and_pointer_loops_are_bounded() {
        let mut message: Vec<u8> = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        message.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        message.extend_from_slice(&[
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34,
        ]);
        let parsed: DnsMessage = dns(&message).expect("parses");
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.answers[0].data, "93.184.216.34");
        let looped: Vec<u8> = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1];
        assert_eq!(dns(&looped), None);
    }

    #[test]
    fn chunked_bodies_reassemble_and_report_truncation() {
        let (body, _, complete): (Vec<u8>, usize, bool) =
            dechunk(b"5\r\nhello\r\n6;x=1\r\n world\r\n0\r\n\r\n");
        assert_eq!(body, b"hello world");
        assert!(complete);
        let (_, _, complete): (Vec<u8>, usize, bool) = dechunk(b"5\r\nhel");
        assert!(!complete);
    }
}
