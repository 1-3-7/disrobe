use super::limits;
use super::object::{ObjId, PdfDict, PdfObject, PdfStream};

#[must_use]
pub const fn is_whitespace(byte: u8) -> bool {
    matches!(byte, 0x00 | 0x09 | 0x0A | 0x0C | 0x0D | 0x20)
}

#[must_use]
pub const fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

#[must_use]
const fn is_regular(byte: u8) -> bool {
    !is_whitespace(byte) && !is_delimiter(byte)
}

#[must_use]
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug)]
pub struct Lexer<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Lexer<'a> {
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    pub const fn at(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    pub fn skip_whitespace_and_comments(&mut self) {
        while let Some(byte) = self.peek() {
            if is_whitespace(byte) {
                self.pos += 1;
            } else if byte == b'%' {
                while let Some(inner) = self.peek() {
                    self.pos += 1;
                    if inner == b'\n' || inner == b'\r' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn read_regular_token(&mut self) -> &'a [u8] {
        let start: usize = self.pos;
        while let Some(byte) = self.peek() {
            if is_regular(byte) {
                self.pos += 1;
            } else {
                break;
            }
        }
        &self.buf[start..self.pos]
    }

    pub fn parse_object(&mut self, depth: usize) -> Option<PdfObject> {
        if depth > limits::MAX_OBJECT_DEPTH {
            return None;
        }
        self.skip_whitespace_and_comments();
        match self.peek()? {
            b'/' => self.parse_name(),
            b'(' => self.parse_literal_string(),
            b'<' => {
                if self.buf.get(self.pos + 1) == Some(&b'<') {
                    self.parse_dictionary_or_stream(depth)
                } else {
                    self.parse_hex_string()
                }
            }
            b'[' => self.parse_array(depth),
            b'0'..=b'9' | b'+' | b'-' | b'.' => Some(self.parse_number_or_reference()),
            b't' | b'f' | b'n' => self.parse_keyword_literal(),
            _ => None,
        }
    }

    fn parse_keyword_literal(&mut self) -> Option<PdfObject> {
        let token: &[u8] = self.read_regular_token();
        match token {
            b"true" => Some(PdfObject::Boolean(true)),
            b"false" => Some(PdfObject::Boolean(false)),
            b"null" => Some(PdfObject::Null),
            _ => None,
        }
    }

    fn parse_name(&mut self) -> Option<PdfObject> {
        self.pos += 1;
        let mut name: Vec<u8> = Vec::new();
        while let Some(byte) = self.peek() {
            if !is_regular(byte) {
                break;
            }
            self.pos += 1;
            if byte == b'#' {
                let high: Option<u8> = self.peek().and_then(hex_value);
                let low: Option<u8> = self.buf.get(self.pos + 1).copied().and_then(hex_value);
                if let (Some(high), Some(low)) = (high, low) {
                    name.push((high << 4) | low);
                    self.pos += 2;
                    continue;
                }
            }
            name.push(byte);
            if name.len() >= limits::MAX_NAME_BYTES {
                break;
            }
        }
        Some(PdfObject::Name(name))
    }

    fn parse_literal_string(&mut self) -> Option<PdfObject> {
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        let mut depth: usize = 1;
        while let Some(byte) = self.peek() {
            self.pos += 1;
            match byte {
                b'\\' => self.decode_escape(&mut out),
                b'(' => {
                    depth += 1;
                    out.push(b'(');
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    out.push(b')');
                }
                b'\r' => {
                    if self.peek() == Some(b'\n') {
                        self.pos += 1;
                    }
                    out.push(b'\n');
                }
                other => out.push(other),
            }
            if out.len() >= limits::MAX_STRING_BYTES {
                break;
            }
        }
        Some(PdfObject::String(out))
    }

    fn decode_escape(&mut self, out: &mut Vec<u8>) {
        let Some(byte): Option<u8> = self.peek() else {
            return;
        };
        self.pos += 1;
        match byte {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0C),
            b'(' => out.push(b'('),
            b')' => out.push(b')'),
            b'\\' => out.push(b'\\'),
            b'\n' => {}
            b'\r' => {
                if self.peek() == Some(b'\n') {
                    self.pos += 1;
                }
            }
            b'0'..=b'7' => {
                let mut value: u16 = u16::from(byte - b'0');
                let mut count: usize = 1;
                while count < 3 {
                    match self.peek() {
                        Some(next @ b'0'..=b'7') => {
                            value = value * 8 + u16::from(next - b'0');
                            self.pos += 1;
                            count += 1;
                        }
                        _ => break,
                    }
                }
                out.push((value & 0xFF) as u8);
            }
            other => out.push(other),
        }
    }

    fn parse_hex_string(&mut self) -> Option<PdfObject> {
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        let mut high: Option<u8> = None;
        while let Some(byte) = self.peek() {
            self.pos += 1;
            if byte == b'>' {
                break;
            }
            if is_whitespace(byte) {
                continue;
            }
            let Some(nibble): Option<u8> = hex_value(byte) else {
                continue;
            };
            match high.take() {
                Some(prev) => out.push((prev << 4) | nibble),
                None => high = Some(nibble),
            }
            if out.len() >= limits::MAX_STRING_BYTES {
                break;
            }
        }
        if let Some(prev) = high {
            out.push(prev << 4);
        }
        Some(PdfObject::String(out))
    }

    fn parse_array(&mut self, depth: usize) -> Option<PdfObject> {
        self.pos += 1;
        let mut items: Vec<PdfObject> = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            match self.peek() {
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                None => break,
                _ => {}
            }
            let before: usize = self.pos;
            match self.parse_object(depth + 1) {
                Some(item) => items.push(item),
                None => {
                    self.pos += 1;
                }
            }
            if self.pos == before {
                self.pos += 1;
            }
            if items.len() >= limits::MAX_ARRAY_ELEMENTS {
                break;
            }
        }
        Some(PdfObject::Array(items))
    }

    fn parse_dictionary_or_stream(&mut self, depth: usize) -> Option<PdfObject> {
        self.pos += 2;
        let mut dict: PdfDict = PdfDict::new();
        loop {
            self.skip_whitespace_and_comments();
            match self.peek() {
                Some(b'>') if self.buf.get(self.pos + 1) == Some(&b'>') => {
                    self.pos += 2;
                    break;
                }
                Some(b'/') => {}
                None => return Some(PdfObject::Dictionary(dict)),
                _ => {
                    self.pos += 1;
                    continue;
                }
            }
            let Some(PdfObject::Name(key)): Option<PdfObject> = self.parse_name() else {
                continue;
            };
            self.skip_whitespace_and_comments();
            let before: usize = self.pos;
            let Some(value): Option<PdfObject> = self.parse_object(depth + 1) else {
                if self.pos == before {
                    self.pos += 1;
                }
                continue;
            };
            dict.push(key, value);
            if dict.len() >= limits::MAX_DICT_ENTRIES {
                break;
            }
        }
        if let Some(stream) = self.try_read_stream(dict.clone()) {
            return Some(PdfObject::Stream(stream));
        }
        Some(PdfObject::Dictionary(dict))
    }

    fn try_read_stream(&mut self, dict: PdfDict) -> Option<PdfStream> {
        let save: usize = self.pos;
        self.skip_whitespace_and_comments();
        if !self.buf[self.pos.min(self.buf.len())..].starts_with(b"stream") {
            self.pos = save;
            return None;
        }
        self.pos += 6;
        if self.peek() == Some(b'\r') {
            self.pos += 1;
        }
        if self.peek() == Some(b'\n') {
            self.pos += 1;
        }
        let data_start: usize = self.pos;
        let end: usize = self.locate_stream_end(&dict, data_start);
        let mut data_end: usize = end;
        if data_end > data_start && self.buf.get(data_end - 1) == Some(&b'\n') {
            data_end -= 1;
            if data_end > data_start && self.buf.get(data_end - 1) == Some(&b'\r') {
                data_end -= 1;
            }
        } else if data_end > data_start && self.buf.get(data_end - 1) == Some(&b'\r') {
            data_end -= 1;
        }
        let raw: Vec<u8> = self.buf.get(data_start..data_end)?.to_vec();
        self.pos = end;
        if self.buf[self.pos.min(self.buf.len())..].starts_with(b"endstream") {
            self.pos += 9;
        }
        Some(PdfStream { dict, raw })
    }

    fn locate_stream_end(&self, dict: &PdfDict, data_start: usize) -> usize {
        if let Some(PdfObject::Integer(length)) = dict.get(b"Length")
            && let Ok(length) = usize::try_from(*length)
            && let Some(candidate) = data_start.checked_add(length)
            && candidate <= self.buf.len()
        {
            let mut probe: Lexer<'_> = Lexer::at(self.buf, candidate);
            probe.skip_whitespace_and_comments();
            if self.buf[probe.pos.min(self.buf.len())..].starts_with(b"endstream") {
                return candidate;
            }
        }
        find_subsequence(self.buf, b"endstream", data_start).unwrap_or(self.buf.len())
    }

    fn parse_number_or_reference(&mut self) -> PdfObject {
        let start: usize = self.pos;
        let token: &[u8] = self.read_regular_token();
        let first: PdfObject = parse_numeric(token);
        let PdfObject::Integer(number) = first else {
            return first;
        };
        if number < 0 {
            return first;
        }
        let save: usize = self.pos;
        self.skip_whitespace_and_comments();
        let generation_token: &[u8] = self.read_regular_token();
        if let PdfObject::Integer(generation) = parse_numeric(generation_token)
            && generation >= 0
            && generation_token.iter().all(u8::is_ascii_digit)
            && !generation_token.is_empty()
        {
            let after_generation: usize = self.pos;
            self.skip_whitespace_and_comments();
            let keyword: &[u8] = self.read_regular_token();
            if keyword == b"R"
                && let Ok(number) = u32::try_from(number)
                && let Ok(generation) = u16::try_from(generation)
            {
                return PdfObject::Reference((number, generation));
            }
            self.pos = after_generation;
        }
        self.pos = save;
        let _ = start;
        first
    }

    pub fn parse_indirect_object(&mut self) -> Option<(ObjId, PdfObject)> {
        self.skip_whitespace_and_comments();
        let number_token: &[u8] = self.read_regular_token();
        if number_token.is_empty() || !number_token.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let number: u32 = parse_uint(number_token)?;
        self.skip_whitespace_and_comments();
        let generation_token: &[u8] = self.read_regular_token();
        if generation_token.is_empty() || !generation_token.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let generation: u16 = u16::try_from(parse_uint(generation_token)?).ok()?;
        self.skip_whitespace_and_comments();
        if self.read_regular_token() != b"obj" {
            return None;
        }
        let object: PdfObject = self.parse_object(0)?;
        Some(((number, generation), object))
    }
}

#[must_use]
pub fn find_subsequence(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
        .map(|offset: usize| from + offset)
}

fn parse_numeric(token: &[u8]) -> PdfObject {
    if token.is_empty() {
        return PdfObject::Null;
    }
    if token.contains(&b'.') || token.contains(&b'e') || token.contains(&b'E') {
        let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(token);
        return text
            .parse::<f64>()
            .map_or(PdfObject::Real(0.0), PdfObject::Real);
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(token);
    text.parse::<i64>()
        .map_or(PdfObject::Real(0.0), PdfObject::Integer)
}

fn parse_uint(token: &[u8]) -> Option<u32> {
    let mut value: u64 = 0;
    for &byte in token {
        let digit: u64 = u64::from(byte.checked_sub(b'0')?);
        if digit > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(digit)?;
        if value > u64::from(u32::MAX) {
            return None;
        }
    }
    u32::try_from(value).ok()
}
