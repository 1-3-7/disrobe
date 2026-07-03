use md5::{Digest, Md5};

const MAX_ARRAY_ELEMENTS: usize = 4096;
const MAX_FOR_INDICES: usize = 4096;
const MAX_PRINTF_BYTES: usize = 65536;
const MAX_TAG_LEN: usize = 1024;

#[derive(Debug, Clone)]
pub(crate) struct TokenArrayLookup {
    pub elements: Vec<String>,
    pub indices: Vec<usize>,
    pub output: String,
}

pub(crate) fn try_token_array_lookup(s: &str) -> Option<TokenArrayLookup> {
    let array: ParsedArray = parse_array_assignment(s)?;
    let for_loop: ParsedForLoop = parse_for_lookup_loop(s, &array.var_name)?;
    let _: bool = for_loop.var_name != array.loop_var_hint_unused;
    let mut out: String = String::with_capacity(for_loop.indices.len());
    for idx in &for_loop.indices {
        let i: usize = *idx;
        if let Some(element) = array.elements.get(i) {
            out.push_str(element);
        }
    }
    Some(TokenArrayLookup {
        elements: array.elements,
        indices: for_loop.indices,
        output: out,
    })
}

#[derive(Debug, Clone)]
struct ParsedArray {
    var_name: String,
    elements: Vec<String>,
    loop_var_hint_unused: String,
}

fn parse_array_assignment(s: &str) -> Option<ParsedArray> {
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    let (name_start, name_end): (usize, usize) = scan_for_assign(bytes, &mut i)?;
    let name: String = std::str::from_utf8(&bytes[name_start..name_end])
        .ok()?
        .to_owned();
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'(' {
        return None;
    }
    i += 1;
    let close: usize = find_matching_paren(bytes, i)?;
    let body: &[u8] = &bytes[i..close];
    let elements: Vec<String> = parse_array_body(body)?;
    if elements.len() > MAX_ARRAY_ELEMENTS {
        return None;
    }
    Some(ParsedArray {
        var_name: name,
        elements,
        loop_var_hint_unused: String::new(),
    })
}

fn scan_for_assign(bytes: &[u8], cursor: &mut usize) -> Option<(usize, usize)> {
    let mut i: usize = *cursor;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            i += 1;
            continue;
        }
        let start: usize = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let name_end: usize = i;
        if i < bytes.len() && bytes[i] == b'=' && i + 1 < bytes.len() {
            let mut j: usize = i + 1;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                *cursor = i + 1;
                return Some((start, name_end));
            }
        }
        i += 1;
    }
    None
}

fn find_matching_paren(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: usize = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'\''
            && let Some(end) = find_single_quote_end(bytes, i + 1)
        {
            i = end + 1;
            continue;
        }
        if b == b'"'
            && let Some(end) = find_double_quote_end(bytes, i + 1)
        {
            i = end + 1;
            continue;
        }
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn find_single_quote_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_double_quote_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_array_body(body: &[u8]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(16);
    let mut i: usize = 0;
    while i < body.len() {
        while i < body.len() && matches!(body[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= body.len() {
            break;
        }
        let mut word: Vec<u8> = Vec::with_capacity(4);
        let mut had_content: bool = false;
        while i < body.len() && !matches!(body[i], b' ' | b'\t' | b'\n' | b'\r') {
            let b: u8 = body[i];
            if b == b'\\' && i + 1 < body.len() {
                word.push(body[i + 1]);
                i += 2;
                had_content = true;
                continue;
            }
            if b == b'\''
                && let Some(end) = find_single_quote_end(body, i + 1)
            {
                word.extend_from_slice(&body[i + 1..end]);
                i = end + 1;
                had_content = true;
                continue;
            }
            if b == b'"'
                && let Some(end) = find_double_quote_end(body, i + 1)
            {
                word.extend_from_slice(&body[i + 1..end]);
                i = end + 1;
                had_content = true;
                continue;
            }
            word.push(b);
            i += 1;
            had_content = true;
        }
        if had_content {
            let s: String = String::from_utf8(word).ok()?;
            out.push(s);
        }
    }
    Some(out)
}

#[derive(Debug, Clone)]
struct ParsedForLoop {
    var_name: String,
    indices: Vec<usize>,
}

fn parse_for_lookup_loop(s: &str, array_var_name: &str) -> Option<ParsedForLoop> {
    let bytes: &[u8] = s.as_bytes();
    let for_idx: usize = find_keyword(bytes, b"for")?;
    let mut i: usize = for_idx + 3;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    let var_start: usize = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    let var_name: String = std::str::from_utf8(&bytes[var_start..i]).ok()?.to_owned();
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    let after_in: &[u8] = bytes.get(i..i + 2)?;
    if after_in != b"in" {
        return None;
    }
    i += 2;
    let in_start: usize = i;
    let in_end: usize = find_for_body_separator(bytes, in_start)?;
    let in_body: &[u8] = &bytes[in_start..in_end];
    let indices: Vec<usize> = parse_index_list(in_body)?;
    if indices.len() > MAX_FOR_INDICES {
        return None;
    }
    let do_idx: usize = find_keyword_from(bytes, b"do", in_end)?;
    let printf_lookup: &[u8] = b"${";
    let after_do: usize = do_idx + 2;
    let array_ref: String = format!("${{{array_var_name}[");
    if !s.as_bytes()[after_do..]
        .windows(array_ref.len())
        .any(|w: &[u8]| w == array_ref.as_bytes())
    {
        let _ = printf_lookup;
        return None;
    }
    let dollar_var: String = format!("${var_name}");
    if !s[after_do..].contains(&dollar_var) {
        return None;
    }
    Some(ParsedForLoop { var_name, indices })
}

fn find_keyword(bytes: &[u8], kw: &[u8]) -> Option<usize> {
    find_keyword_from(bytes, kw, 0)
}

fn find_keyword_from(bytes: &[u8], kw: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i + kw.len() <= bytes.len() {
        let prev: u8 = if i == 0 { b' ' } else { bytes[i - 1] };
        let after: u8 = bytes.get(i + kw.len()).copied().unwrap_or(b' ');
        let prev_ok: bool = matches!(prev, b' ' | b'\t' | b'\n' | b'\r' | b';' | b'(' | b'{');
        let after_ok: bool = matches!(after, b' ' | b'\t' | b'\n' | b'\r' | b';');
        if prev_ok && after_ok && &bytes[i..i + kw.len()] == kw {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_for_body_separator(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == b';' {
            return Some(i);
        }
        if bytes[i] == b'\n' {
            let mut j: usize = i + 1;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            if j + 2 <= bytes.len() && &bytes[j..j + 2] == b"do" {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn parse_index_list(body: &[u8]) -> Option<Vec<usize>> {
    let mut out: Vec<usize> = Vec::with_capacity(16);
    let mut i: usize = 0;
    while i < body.len() {
        while i < body.len() && matches!(body[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= body.len() {
            break;
        }
        let start: usize = i;
        while i < body.len() && body[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let n: usize = std::str::from_utf8(&body[start..i]).ok()?.parse().ok()?;
        out.push(n);
    }
    Some(out)
}

#[derive(Debug, Clone)]
pub(crate) struct StringSplitDecoded {
    pub bytes_emitted: usize,
    pub output: String,
}

pub(crate) fn try_string_split_indirection(s: &str) -> Option<StringSplitDecoded> {
    let chunks: Vec<HexByteChunk> = scan_hex_byte_chunks(s);
    if chunks.is_empty() {
        return None;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(chunks.len());
    for chunk in &chunks {
        let hex: String = compute_md5_cut(&chunk.tag, chunk.cut_start, chunk.cut_end);
        if hex.len() < 2 {
            return None;
        }
        let pair: &str = &hex[..2];
        let byte: u8 = u8::from_str_radix(pair, 16).ok()?;
        buf.push(byte);
        if buf.len() > MAX_PRINTF_BYTES {
            return None;
        }
    }
    let decoded: String = String::from_utf8(buf.clone())
        .unwrap_or_else(|_: std::string::FromUtf8Error| String::from_utf8_lossy(&buf).into_owned());
    Some(StringSplitDecoded {
        bytes_emitted: chunks.len(),
        output: decoded,
    })
}

#[derive(Debug, Clone)]
struct HexByteChunk {
    tag: String,
    cut_start: usize,
    cut_end: usize,
}

fn scan_hex_byte_chunks(s: &str) -> Vec<HexByteChunk> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<HexByteChunk> = Vec::new();
    let needle: &[u8] = b"\\x$(";
    let mut i: usize = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        let inner_start: usize = i + needle.len();
        let end: Option<usize> = find_structured_chunk_end(bytes, inner_start);
        let Some(end_idx) = end else {
            i += 1;
            continue;
        };
        let inner_bytes: &[u8] = &bytes[inner_start..end_idx];
        let Ok(inner) = std::str::from_utf8(inner_bytes) else {
            i = end_idx + 1;
            continue;
        };
        if let Some(chunk) = parse_md5_cut_chunk(inner) {
            out.push(chunk);
            i = end_idx + 1;
            continue;
        }
        i += 1;
    }
    out
}

fn find_structured_chunk_end(bytes: &[u8], start: usize) -> Option<usize> {
    let cut_marker: &[u8] = b"cut";
    let mut i: usize = start;
    while i + cut_marker.len() <= bytes.len() {
        if &bytes[i..i + cut_marker.len()] == cut_marker {
            let prev: u8 = if i == 0 { b' ' } else { bytes[i - 1] };
            let after: u8 = bytes.get(i + cut_marker.len()).copied().unwrap_or(b' ');
            if matches!(prev, b' ' | b'\t' | b'|') && matches!(after, b' ' | b'\t') {
                let mut j: usize = i + cut_marker.len();
                while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                    j += 1;
                }
                if j + 2 > bytes.len() || &bytes[j..j + 2] != b"-b" {
                    i += 1;
                    continue;
                }
                j += 2;
                while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                    j += 1;
                }
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if j >= bytes.len() || bytes[j] != b'-' {
                    i += 1;
                    continue;
                }
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b')' {
                    return Some(j);
                }
                i += 1;
                continue;
            }
        }
        i += 1;
    }
    None
}

fn parse_md5_cut_chunk(inner: &str) -> Option<HexByteChunk> {
    let tag: String = extract_printf_tag(inner)?;
    if tag.len() > MAX_TAG_LEN {
        return None;
    }
    if !inner.contains("md5sum") && !inner.contains("md\\5sum") {
        return None;
    }
    let (cut_start, cut_end): (usize, usize) = extract_cut_range(inner)?;
    Some(HexByteChunk {
        tag,
        cut_start,
        cut_end,
    })
}

fn extract_printf_tag(inner: &str) -> Option<String> {
    let bytes: &[u8] = inner.as_bytes();
    let printf_pos: usize = find_byte_seq(bytes, b"printf")?;
    let mut i: usize = printf_pos + 6;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"%s" {
        i += 2;
    } else {
        return None;
    }
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    if bytes[i] == b'\'' {
        let end: usize = find_single_quote_end(bytes, i + 1)?;
        return std::str::from_utf8(&bytes[i + 1..end])
            .ok()
            .map(|s: &str| s.to_owned());
    }
    if bytes[i] == b'"' {
        let end: usize = find_double_quote_end(bytes, i + 1)?;
        return std::str::from_utf8(&bytes[i + 1..end])
            .ok()
            .map(|s: &str| s.to_owned());
    }
    let start: usize = i;
    while i < bytes.len() {
        if bytes[i] == b'|' {
            break;
        }
        if matches!(bytes[i], b' ' | b'\t')
            && let Some(next) = bytes.get(i + 1..)
            && next
                .iter()
                .take_while(|b: &&u8| matches!(**b, b' ' | b'\t'))
                .count()
                + i
                < bytes.len()
        {
            let mut j: usize = i;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'|' {
                break;
            }
        }
        i += 1;
    }
    while i > start && matches!(bytes[i - 1], b' ' | b'\t') {
        i -= 1;
    }
    std::str::from_utf8(&bytes[start..i])
        .ok()
        .map(|s: &str| s.to_owned())
}

fn extract_cut_range(inner: &str) -> Option<(usize, usize)> {
    let bytes: &[u8] = inner.as_bytes();
    let cut_pos: usize = find_byte_seq(bytes, b"cut")?;
    let mut i: usize = cut_pos + 3;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i + 2 > bytes.len() || &bytes[i..i + 2] != b"-b" {
        return None;
    }
    i += 2;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    let n_start: usize = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let n: usize = std::str::from_utf8(&bytes[n_start..i]).ok()?.parse().ok()?;
    if i >= bytes.len() || bytes[i] != b'-' {
        return None;
    }
    i += 1;
    let m_start: usize = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let m: usize = std::str::from_utf8(&bytes[m_start..i]).ok()?.parse().ok()?;
    if m < n {
        return None;
    }
    Some((n, m))
}

fn find_byte_seq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

fn compute_md5_cut(tag: &str, cut_start: usize, cut_end: usize) -> String {
    let mut hasher: Md5 = Md5::new();
    hasher.update(tag.as_bytes());
    let digest: [u8; 16] = hasher.finalize().into();
    let mut hex: String = String::with_capacity(32);
    let table: &[u8; 16] = b"0123456789abcdef";
    for byte in &digest {
        let value: u8 = *byte;
        hex.push(char::from(table[usize::from(value >> 4)]));
        hex.push(char::from(table[usize::from(value & 0x0f)]));
    }
    let lo: usize = cut_start.saturating_sub(1);
    let hi: usize = cut_end.min(hex.len());
    if lo >= hi {
        return String::new();
    }
    hex[lo..hi].to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn md5_cut_matches_known_first_byte() {
        let hex: String = compute_md5_cut("mM%U", 22, 23);
        assert_eq!(hex, "65");
    }

    #[test]
    fn parses_simple_array_and_for_loop() {
        let src: &str = r"X=( a b c d e ) ; for v in 4 3 0 ; do printf %s ${X[$v]} ; done";
        let r: TokenArrayLookup = try_token_array_lookup(src).expect("parsed");
        assert_eq!(r.elements, vec!["a", "b", "c", "d", "e"]);
        assert_eq!(r.indices, vec![4, 3, 0]);
        assert_eq!(r.output, "eda");
    }

    #[test]
    fn rejects_for_loop_without_array_reference() {
        let src: &str = r"X=( a b ) ; for v in 1 0 ; do echo $v ; done";
        assert!(try_token_array_lookup(src).is_none());
    }

    #[test]
    fn extracts_cut_range() {
        let (n, m): (usize, usize) =
            extract_cut_range("printf %s 'tag' | md5sum | cut -b 12-15").expect("ok");
        assert_eq!((n, m), (12usize, 15usize));
    }

    #[test]
    fn extracts_printf_tag_single_quoted() {
        let tag: String = extract_printf_tag("printf %s 'abc' | md5sum").expect("ok");
        assert_eq!(tag, "abc");
    }
}
