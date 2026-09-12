use super::filters::{Decoded, decode_stream};
use super::limits;
use super::object::{PdfDict, PdfDocument, PdfObject};
use super::parse::{Lexer, find_subsequence, is_delimiter, is_whitespace};

#[must_use]
pub fn load(buf: &[u8]) -> PdfDocument {
    let mut doc: PdfDocument = PdfDocument::default();
    brute_force(buf, &mut doc);
    parse_xref_chain(buf, &mut doc);
    if let Some(dict) = scan_trailer_keyword(buf) {
        merge_trailer(&mut doc, &dict);
    }
    if let Some(encryption) = super::crypt::detect(&doc) {
        super::crypt::decrypt_document(&mut doc, &encryption);
    }
    expand_object_streams(&mut doc);
    ensure_root(&mut doc);
    doc.recovered_by_scan = !doc.xref_table_seen && !doc.xref_stream_seen;
    doc
}

fn insert_object(doc: &mut PdfDocument, number: u32, generation: u16, object: PdfObject) {
    if doc.objects.len() >= limits::MAX_OBJECTS && !doc.objects.contains_key(&number) {
        return;
    }
    doc.objects.insert(number, (generation, object));
}

fn brute_force(buf: &[u8], doc: &mut PdfDocument) {
    let mut index: usize = 0;
    while index + 3 <= buf.len() {
        if &buf[index..index + 3] != b"obj" {
            index += 1;
            continue;
        }
        let after: bool = buf
            .get(index + 3)
            .is_none_or(|byte: &u8| is_whitespace(*byte) || is_delimiter(*byte));
        if !after {
            index += 1;
            continue;
        }
        let Some(start): Option<usize> = header_start(buf, index) else {
            index += 3;
            continue;
        };
        let mut lexer: Lexer<'_> = Lexer::at(buf, start);
        match lexer.parse_indirect_object() {
            Some(((number, generation), object)) => {
                insert_object(doc, number, generation, object);
                index = lexer.pos.max(index + 3);
            }
            None => index += 3,
        }
        if doc.objects.len() >= limits::MAX_OBJECTS {
            break;
        }
    }
}

fn header_start(buf: &[u8], obj_pos: usize) -> Option<usize> {
    let mut cursor: usize = obj_pos;
    cursor = skip_whitespace_left(buf, cursor);
    cursor = read_digits_left(buf, cursor)?;
    cursor = skip_whitespace_left(buf, cursor);
    read_digits_left(buf, cursor)
}

fn skip_whitespace_left(buf: &[u8], mut cursor: usize) -> usize {
    while cursor > 0 && is_whitespace(buf[cursor - 1]) {
        cursor -= 1;
    }
    cursor
}

fn read_digits_left(buf: &[u8], mut cursor: usize) -> Option<usize> {
    if cursor == 0 || !buf[cursor - 1].is_ascii_digit() {
        return None;
    }
    while cursor > 0 && buf[cursor - 1].is_ascii_digit() {
        cursor -= 1;
    }
    Some(cursor)
}

fn expand_object_streams(doc: &mut PdfDocument) {
    let stream_numbers: Vec<u32> = doc
        .objects
        .iter()
        .filter(|(_, (_, obj)): &(&u32, &(u16, PdfObject))| {
            obj.as_stream()
                .is_some_and(|stream| stream.dict.type_name() == Some(b"ObjStm"))
        })
        .map(|(number, _): (&u32, &(u16, PdfObject))| *number)
        .collect();
    for number in stream_numbers {
        let Some((_, PdfObject::Stream(stream))): Option<(u16, PdfObject)> =
            doc.objects.get(&number).cloned()
        else {
            continue;
        };
        let count: usize = doc
            .dict_get(&stream.dict, b"N")
            .and_then(PdfObject::as_i64)
            .and_then(|value: i64| usize::try_from(value).ok())
            .unwrap_or(0)
            .min(limits::MAX_OBJSTM_OBJECTS);
        let first: usize = doc
            .dict_get(&stream.dict, b"First")
            .and_then(PdfObject::as_i64)
            .and_then(|value: i64| usize::try_from(value).ok())
            .unwrap_or(0);
        let decoded: Decoded = decode_stream(doc, &stream);
        parse_object_stream(doc, &decoded.data, count, first);
    }
}

fn parse_object_stream(doc: &mut PdfDocument, data: &[u8], count: usize, first: usize) {
    let mut header: Lexer<'_> = Lexer::new(data);
    let mut entries: Vec<(u32, usize)> = Vec::with_capacity(count);
    for _ in 0..count {
        header.skip_whitespace_and_comments();
        let Some(number): Option<u32> = read_uint_token(&mut header) else {
            break;
        };
        header.skip_whitespace_and_comments();
        let Some(offset): Option<u32> = read_uint_token(&mut header) else {
            break;
        };
        entries.push((number, offset as usize));
    }
    for (number, offset) in entries {
        if doc.objects.contains_key(&number) {
            continue;
        }
        let Some(position): Option<usize> = first.checked_add(offset) else {
            continue;
        };
        if position > data.len() {
            continue;
        }
        let mut body: Lexer<'_> = Lexer::at(data, position);
        if let Some(object) = body.parse_object(0) {
            insert_object(doc, number, 0, object);
        }
    }
}

fn read_uint_token(lexer: &mut Lexer<'_>) -> Option<u32> {
    let start: usize = lexer.pos;
    while lexer.buf.get(lexer.pos).is_some_and(u8::is_ascii_digit) {
        lexer.pos += 1;
    }
    if lexer.pos == start {
        return None;
    }
    let mut value: u64 = 0;
    for &byte in &lexer.buf[start..lexer.pos] {
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
        if value > u64::from(u32::MAX) {
            return None;
        }
    }
    u32::try_from(value).ok()
}

fn parse_xref_chain(buf: &[u8], doc: &mut PdfDocument) {
    let Some(mut offset): Option<usize> = parse_startxref(buf) else {
        return;
    };
    doc.startxref_ok = true;
    let mut visited: Vec<usize> = Vec::new();
    let mut steps: usize = 0;
    loop {
        if steps >= limits::MAX_XREF_CHAIN || visited.contains(&offset) || offset >= buf.len() {
            break;
        }
        visited.push(offset);
        steps += 1;
        let Some(trailer): Option<PdfDict> = parse_xref_section(buf, offset, doc) else {
            break;
        };
        if let Some(hybrid) = trailer
            .get(b"XRefStm")
            .and_then(PdfObject::as_i64)
            .and_then(|value: i64| usize::try_from(value).ok())
            && hybrid < buf.len()
            && !visited.contains(&hybrid)
        {
            visited.push(hybrid);
            let _ = parse_xref_section(buf, hybrid, doc);
        }
        merge_trailer(doc, &trailer);
        match trailer
            .get(b"Prev")
            .and_then(PdfObject::as_i64)
            .and_then(|value: i64| usize::try_from(value).ok())
        {
            Some(previous) => offset = previous,
            None => break,
        }
    }
}

fn parse_startxref(buf: &[u8]) -> Option<usize> {
    let tail_start: usize = buf.len().saturating_sub(2048);
    let position: usize = find_last_subsequence(&buf[tail_start..], b"startxref")? + tail_start;
    let mut lexer: Lexer<'_> = Lexer::at(buf, position + 9);
    lexer.skip_whitespace_and_comments();
    read_uint_token(&mut lexer).map(|value: u32| value as usize)
}

fn find_last_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&index| &haystack[index..index + needle.len()] == needle)
}

fn parse_xref_section(buf: &[u8], offset: usize, doc: &mut PdfDocument) -> Option<PdfDict> {
    let mut lexer: Lexer<'_> = Lexer::at(buf, offset);
    lexer.skip_whitespace_and_comments();
    if buf.get(lexer.pos..lexer.pos + 4) == Some(b"xref") {
        doc.xref_table_seen = true;
        return parse_xref_table(buf, lexer.pos + 4, doc);
    }
    doc.xref_stream_seen = true;
    let mut object_lexer: Lexer<'_> = Lexer::at(buf, offset);
    let (_, object): (_, PdfObject) = object_lexer.parse_indirect_object()?;
    let stream: &super::object::PdfStream = object.as_stream()?;
    let dict: PdfDict = stream.dict.clone();
    let stream_owned: super::object::PdfStream = stream.clone();
    parse_xref_stream(buf, doc, &stream_owned);
    Some(dict)
}

fn parse_xref_table(buf: &[u8], start: usize, doc: &mut PdfDocument) -> Option<PdfDict> {
    let mut lexer: Lexer<'_> = Lexer::at(buf, start);
    let mut located: Vec<(u32, usize)> = Vec::new();
    loop {
        lexer.skip_whitespace_and_comments();
        if buf.get(lexer.pos..lexer.pos + 7) == Some(b"trailer") {
            lexer.pos += 7;
            let trailer: Option<PdfDict> =
                lexer.parse_object(0).and_then(|obj: PdfObject| match obj {
                    PdfObject::Dictionary(dict) => Some(dict),
                    _ => None,
                });
            recover_located(buf, doc, &located);
            return trailer;
        }
        let Some(first_number): Option<u32> = read_uint_token(&mut lexer) else {
            recover_located(buf, doc, &located);
            return None;
        };
        lexer.skip_whitespace_and_comments();
        let Some(count): Option<u32> = read_uint_token(&mut lexer) else {
            recover_located(buf, doc, &located);
            return None;
        };
        for row in 0..count.min(limits::MAX_XREF_ENTRIES as u32) {
            lexer.skip_whitespace_and_comments();
            let offset: Option<u32> = read_uint_token(&mut lexer);
            lexer.skip_whitespace_and_comments();
            let _ = read_uint_token(&mut lexer);
            lexer.skip_whitespace_and_comments();
            let in_use: bool = buf.get(lexer.pos) == Some(&b'n');
            if matches!(buf.get(lexer.pos), Some(b'n' | b'f')) {
                lexer.pos += 1;
            }
            if in_use
                && let Some(offset) = offset
                && let Some(number) = first_number.checked_add(row)
            {
                located.push((number, offset as usize));
            }
        }
    }
}

fn parse_xref_stream(buf: &[u8], doc: &mut PdfDocument, stream: &super::object::PdfStream) {
    let widths: Vec<usize> = match doc.dict_get(&stream.dict, b"W").map(PdfObject::as_array) {
        Some(Some(items)) => items
            .iter()
            .filter_map(|item: &PdfObject| item.as_i64())
            .filter_map(|value: i64| usize::try_from(value).ok())
            .collect(),
        _ => return,
    };
    if widths.len() != 3
        || widths
            .iter()
            .any(|width: &usize| *width > limits::MAX_XREF_FIELD_WIDTH)
    {
        return;
    }
    let size: i64 = doc
        .dict_get(&stream.dict, b"Size")
        .and_then(PdfObject::as_i64)
        .unwrap_or(0);
    let index: Vec<i64> = match doc
        .dict_get(&stream.dict, b"Index")
        .map(PdfObject::as_array)
    {
        Some(Some(items)) => items.iter().filter_map(PdfObject::as_i64).collect(),
        _ => vec![0, size],
    };
    let decoded: Decoded = decode_stream(doc, stream);
    let Some(row_width): Option<usize> = widths[0]
        .checked_add(widths[1])
        .and_then(|partial: usize| partial.checked_add(widths[2]))
        .filter(|width: &usize| *width != 0)
    else {
        return;
    };
    let mut located: Vec<(u32, usize)> = Vec::new();
    let mut cursor: usize = 0;
    for pair in index.chunks(2) {
        let [start, count] = pair else { continue };
        let count: usize = usize::try_from(*count)
            .unwrap_or(0)
            .min(limits::MAX_XREF_ENTRIES);
        for delta in 0..count {
            let Some(end): Option<usize> = cursor.checked_add(row_width) else {
                break;
            };
            let Some(row): Option<&[u8]> = decoded.data.get(cursor..end) else {
                break;
            };
            cursor = end;
            let number: i64 = start.wrapping_add(delta as i64);
            let kind: u64 = if widths[0] == 0 {
                1
            } else {
                read_field(row, 0, widths[0])
            };
            let field2: u64 = read_field(row, widths[0], widths[1]);
            if kind == 1
                && let Ok(target) = u32::try_from(number)
                && let Ok(offset) = usize::try_from(field2)
            {
                located.push((target, offset));
            }
        }
    }
    recover_located(buf, doc, &located);
}

fn read_field(row: &[u8], offset: usize, width: usize) -> u64 {
    offset
        .checked_add(width)
        .and_then(|end: usize| row.get(offset..end))
        .map(read_be)
        .unwrap_or(0)
}

fn recover_located(buf: &[u8], doc: &mut PdfDocument, located: &[(u32, usize)]) {
    for &(number, offset) in located {
        if doc.objects.contains_key(&number) || offset >= buf.len() {
            continue;
        }
        let mut lexer: Lexer<'_> = Lexer::at(buf, offset);
        if let Some(((parsed, generation), object)) = lexer.parse_indirect_object()
            && parsed == number
        {
            insert_object(doc, number, generation, object);
        }
    }
}

fn read_be(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |acc: u64, byte: &u8| (acc << 8) | u64::from(*byte))
}

fn merge_trailer(doc: &mut PdfDocument, trailer: &PdfDict) {
    for (key, value) in trailer.iter() {
        if doc.trailer.get(key).is_none() {
            doc.trailer.push(key.to_vec(), value.clone());
        }
    }
}

fn ensure_root(doc: &mut PdfDocument) {
    if doc.trailer.get(b"Root").is_some() {
        return;
    }
    let xref_dict: Option<PdfDict> = doc
        .objects
        .values()
        .filter_map(|(_, obj): &(u16, PdfObject)| obj.as_dict())
        .find(|dict: &&PdfDict| dict.type_name() == Some(b"XRef"))
        .cloned();
    if let Some(dict) = xref_dict {
        merge_trailer(doc, &dict);
    }
    if doc.trailer.get(b"Root").is_some() {
        return;
    }
    let catalog: Option<u32> = doc
        .objects
        .iter()
        .find(|(_, (_, obj)): &(&u32, &(u16, PdfObject))| {
            obj.as_dict().and_then(PdfDict::type_name) == Some(b"Catalog")
        })
        .map(|(number, _): (&u32, &(u16, PdfObject))| *number);
    if let Some(number) = catalog {
        doc.trailer
            .push(b"Root".to_vec(), PdfObject::Reference((number, 0)));
    }
}

fn scan_trailer_keyword(buf: &[u8]) -> Option<PdfDict> {
    let mut best: Option<PdfDict> = None;
    let mut from: usize = 0;
    while let Some(position) = find_subsequence(buf, b"trailer", from) {
        let mut lexer: Lexer<'_> = Lexer::at(buf, position + 7);
        if let Some(PdfObject::Dictionary(dict)) = lexer.parse_object(0)
            && dict.get(b"Root").is_some()
        {
            best = Some(dict);
        }
        from = position + 7;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::super::object::PdfStream;
    use super::*;

    fn crafted_xref_stream(widths: Vec<PdfObject>) -> PdfStream {
        let mut dict: PdfDict = PdfDict::new();
        dict.push(b"Type".to_vec(), PdfObject::Name(b"XRef".to_vec()));
        dict.push(b"W".to_vec(), PdfObject::Array(widths));
        dict.push(b"Size".to_vec(), PdfObject::Integer(4));
        dict.push(
            b"Index".to_vec(),
            PdfObject::Array(vec![PdfObject::Integer(0), PdfObject::Integer(4)]),
        );
        PdfStream {
            dict,
            raw: vec![0u8; 64],
        }
    }

    #[test]
    fn absurd_xref_widths_recover_nothing_without_panicking() {
        let cases: Vec<Vec<PdfObject>> = vec![
            vec![
                PdfObject::Integer(i64::MAX),
                PdfObject::Integer(i64::MAX),
                PdfObject::Integer(i64::MAX),
            ],
            vec![
                PdfObject::Integer(i64::MAX),
                PdfObject::Integer(i64::MAX),
                PdfObject::Integer(3),
            ],
            vec![
                PdfObject::Integer(9),
                PdfObject::Integer(9),
                PdfObject::Integer(9),
            ],
        ];
        for widths in cases {
            let stream: PdfStream = crafted_xref_stream(widths);
            let mut doc: PdfDocument = PdfDocument::default();
            parse_xref_stream(b"", &mut doc, &stream);
            assert!(
                doc.objects.is_empty(),
                "crafted xref widths must recover nothing"
            );
        }
    }
}
