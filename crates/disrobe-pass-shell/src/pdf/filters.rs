use std::io::Read;

use flate2::read::{DeflateDecoder, ZlibDecoder};

use super::limits;
use super::object::{PdfDict, PdfDocument, PdfObject, PdfStream};

#[derive(Debug, Clone, Default)]
pub struct Decoded {
    pub data: Vec<u8>,
    pub filters: Vec<String>,
    pub capped: bool,
    pub image_filter: Option<String>,
}

#[must_use]
pub fn decode_stream(doc: &PdfDocument, stream: &PdfStream) -> Decoded {
    if doc.total_decoded.get() >= limits::MAX_TOTAL_OUTPUT {
        return Decoded {
            data: Vec::new(),
            filters: Vec::new(),
            capped: true,
            image_filter: None,
        };
    }
    let stages: Vec<(Vec<u8>, Option<PdfDict>)> = filter_stages(doc, &stream.dict);
    let mut data: Vec<u8> = stream.raw.clone();
    let mut applied: Vec<String> = Vec::new();
    let mut capped: bool = false;
    let mut image_filter: Option<String> = None;
    for (index, (name, parms)) in stages.into_iter().enumerate() {
        if index >= limits::MAX_FILTER_CHAIN {
            break;
        }
        let label: String = String::from_utf8_lossy(&name).into_owned();
        match name.as_slice() {
            b"FlateDecode" | b"Fl" => {
                let (decoded, hit): (Vec<u8>, bool) = inflate(&data);
                data = apply_predictor(doc, &decoded, parms.as_ref());
                capped |= hit;
            }
            b"LZWDecode" | b"LZW" => {
                let early: bool = early_change(doc, parms.as_ref());
                let (decoded, hit): (Vec<u8>, bool) = lzw_decode(&data, early);
                data = apply_predictor(doc, &decoded, parms.as_ref());
                capped |= hit;
            }
            b"ASCII85Decode" | b"A85" => {
                let (decoded, hit): (Vec<u8>, bool) = ascii85_decode(&data);
                data = decoded;
                capped |= hit;
            }
            b"ASCIIHexDecode" | b"AHx" => {
                data = ascii_hex_decode(&data);
            }
            b"RunLengthDecode" | b"RL" => {
                let (decoded, hit): (Vec<u8>, bool) = run_length_decode(&data);
                data = decoded;
                capped |= hit;
            }
            b"DCTDecode" | b"JPXDecode" | b"JBIG2Decode" | b"CCITTFaxDecode" => {
                image_filter = Some(label);
                break;
            }
            _ => {
                applied.push(label);
                continue;
            }
        }
        applied.push(label);
        if data.len() >= limits::MAX_STREAM_OUTPUT {
            capped = true;
            data.truncate(limits::MAX_STREAM_OUTPUT);
        }
    }
    let running_total: usize = doc
        .total_decoded
        .get()
        .saturating_add(data.len())
        .min(limits::MAX_TOTAL_OUTPUT);
    doc.total_decoded.set(running_total);
    Decoded {
        data,
        filters: applied,
        capped,
        image_filter,
    }
}

fn filter_stages(doc: &PdfDocument, dict: &PdfDict) -> Vec<(Vec<u8>, Option<PdfDict>)> {
    let names: Vec<Vec<u8>> = match dict.get(b"Filter").map(|obj: &PdfObject| doc.resolve(obj)) {
        Some(PdfObject::Name(name)) => vec![name.clone()],
        Some(PdfObject::Array(items)) => items
            .iter()
            .filter_map(|item: &PdfObject| doc.resolve(item).as_name().map(<[u8]>::to_vec))
            .collect(),
        _ => return Vec::new(),
    };
    let parms_source: Option<&PdfObject> = dict
        .get(b"DecodeParms")
        .or_else(|| dict.get(b"DP"))
        .map(|obj: &PdfObject| doc.resolve(obj));
    let mut stages: Vec<(Vec<u8>, Option<PdfDict>)> = Vec::with_capacity(names.len());
    for (index, name) in names.into_iter().enumerate() {
        let parm: Option<PdfDict> = match parms_source {
            Some(PdfObject::Dictionary(single)) if index == 0 => Some(single.clone()),
            Some(PdfObject::Array(items)) => items
                .get(index)
                .map(|item: &PdfObject| doc.resolve(item))
                .and_then(PdfObject::as_dict)
                .cloned(),
            _ => None,
        };
        stages.push((name, parm));
    }
    stages
}

fn bounded_collect<R: Read>(reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut limited: std::io::Take<R> = reader.take(cap as u64 + 1);
    let _ = limited.read_to_end(&mut out);
    let capped: bool = out.len() > cap;
    out.truncate(cap);
    (out, capped)
}

fn inflate(data: &[u8]) -> (Vec<u8>, bool) {
    let start: usize = data
        .iter()
        .position(|byte: &u8| !super::parse::is_whitespace(*byte))
        .unwrap_or(0);
    let body: &[u8] = &data[start..];
    let (zlib, zlib_hit): (Vec<u8>, bool) =
        bounded_collect(ZlibDecoder::new(body), limits::MAX_STREAM_OUTPUT);
    if !zlib.is_empty() {
        return (zlib, zlib_hit);
    }
    bounded_collect(DeflateDecoder::new(body), limits::MAX_STREAM_OUTPUT)
}

fn early_change(doc: &PdfDocument, parms: Option<&PdfDict>) -> bool {
    parms
        .and_then(|dict: &PdfDict| doc.dict_get(dict, b"EarlyChange"))
        .and_then(PdfObject::as_i64)
        .is_none_or(|value: i64| value != 0)
}

fn lzw_decode(data: &[u8], early_change: bool) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut table: Vec<Vec<u8>> = base_lzw_table();
    let mut code_width: u32 = 9;
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut previous: Option<Vec<u8>> = None;
    let early: usize = usize::from(early_change);
    for &byte in data {
        bit_buffer = (bit_buffer << 8) | u32::from(byte);
        bit_count += 8;
        while bit_count >= code_width {
            bit_count -= code_width;
            let code: usize = ((bit_buffer >> bit_count) & ((1 << code_width) - 1)) as usize;
            match code {
                256 => {
                    table = base_lzw_table();
                    code_width = 9;
                    previous = None;
                    continue;
                }
                257 => {
                    out.truncate(out.len().min(limits::MAX_STREAM_OUTPUT));
                    return (out, false);
                }
                _ => {}
            }
            let entry: Vec<u8> = if let Some(existing) = table.get(code) {
                existing.clone()
            } else if let Some(prev) = &previous {
                let mut built: Vec<u8> = prev.clone();
                if let Some(first) = prev.first() {
                    built.push(*first);
                }
                built
            } else {
                continue;
            };
            out.extend_from_slice(&entry);
            if out.len() >= limits::MAX_STREAM_OUTPUT {
                out.truncate(limits::MAX_STREAM_OUTPUT);
                return (out, true);
            }
            if let Some(prev) = previous.take() {
                let mut new_entry: Vec<u8> = prev;
                if let Some(first) = entry.first() {
                    new_entry.push(*first);
                }
                if table.len() < limits::MAX_OBJSTM_OBJECTS {
                    table.push(new_entry);
                }
            }
            previous = Some(entry);
            if table.len() + early >= (1usize << code_width) && code_width < 12 {
                code_width += 1;
            }
        }
    }
    (out, false)
}

fn base_lzw_table() -> Vec<Vec<u8>> {
    let mut table: Vec<Vec<u8>> = (0..256).map(|value: usize| vec![value as u8]).collect();
    table.push(Vec::new());
    table.push(Vec::new());
    table
}

fn ascii85_decode(data: &[u8]) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut group: [u8; 5] = [0; 5];
    let mut count: usize = 0;
    let mut index: usize = if data.starts_with(b"<~") { 2 } else { 0 };
    while let Some(&byte) = data.get(index) {
        index += 1;
        match byte {
            b'~' => break,
            b'z' if count == 0 => out.extend_from_slice(&[0, 0, 0, 0]),
            b'!'..=b'u' => {
                group[count] = byte - b'!';
                count += 1;
                if count == 5 {
                    push_ascii85_group(group, 5, &mut out);
                    count = 0;
                }
            }
            _ => {}
        }
        if out.len() >= limits::MAX_STREAM_OUTPUT {
            out.truncate(limits::MAX_STREAM_OUTPUT);
            return (out, true);
        }
    }
    if count > 0 {
        for slot in group.iter_mut().skip(count) {
            *slot = 84;
        }
        push_ascii85_group(group, count, &mut out);
    }
    (out, false)
}

fn push_ascii85_group(group: [u8; 5], count: usize, out: &mut Vec<u8>) {
    let mut value: u32 = 0;
    for digit in group {
        value = value.wrapping_mul(85).wrapping_add(u32::from(digit));
    }
    let bytes: [u8; 4] = value.to_be_bytes();
    for &byte in bytes.iter().take(count.saturating_sub(1)) {
        out.push(byte);
    }
}

fn ascii_hex_decode(data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut high: Option<u8> = None;
    for &byte in data {
        if byte == b'>' {
            break;
        }
        let nibble: u8 = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => continue,
        };
        match high.take() {
            Some(prev) => out.push((prev << 4) | nibble),
            None => high = Some(nibble),
        }
        if out.len() >= limits::MAX_STREAM_OUTPUT {
            break;
        }
    }
    if let Some(prev) = high {
        out.push(prev << 4);
    }
    out
}

fn run_length_decode(data: &[u8]) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut index: usize = 0;
    while let Some(&length) = data.get(index) {
        index += 1;
        if length == 128 {
            break;
        }
        if length < 128 {
            let take: usize = usize::from(length) + 1;
            for _ in 0..take {
                let Some(&byte): Option<&u8> = data.get(index) else {
                    return (out, false);
                };
                out.push(byte);
                index += 1;
            }
        } else {
            let repeat: usize = 257 - usize::from(length);
            let Some(&byte): Option<&u8> = data.get(index) else {
                break;
            };
            index += 1;
            out.extend(std::iter::repeat_n(byte, repeat));
        }
        if out.len() >= limits::MAX_STREAM_OUTPUT {
            out.truncate(limits::MAX_STREAM_OUTPUT);
            return (out, true);
        }
    }
    (out, false)
}

fn apply_predictor(doc: &PdfDocument, data: &[u8], parms: Option<&PdfDict>) -> Vec<u8> {
    let Some(parms): Option<&PdfDict> = parms else {
        return data.to_vec();
    };
    let predictor: i64 = doc
        .dict_get(parms, b"Predictor")
        .and_then(PdfObject::as_i64)
        .unwrap_or(1);
    if predictor <= 1 {
        return data.to_vec();
    }
    let columns: usize = doc
        .dict_get(parms, b"Columns")
        .and_then(PdfObject::as_i64)
        .and_then(|value: i64| usize::try_from(value).ok())
        .unwrap_or(1)
        .clamp(1, limits::MAX_PREDICTOR_COLUMNS);
    let colors: usize = doc
        .dict_get(parms, b"Colors")
        .and_then(PdfObject::as_i64)
        .and_then(|value: i64| usize::try_from(value).ok())
        .unwrap_or(1)
        .clamp(1, 16);
    let bits: usize = doc
        .dict_get(parms, b"BitsPerComponent")
        .and_then(PdfObject::as_i64)
        .and_then(|value: i64| usize::try_from(value).ok())
        .unwrap_or(8)
        .clamp(1, 16);
    let bytes_per_pixel: usize = (colors * bits).div_ceil(8).max(1);
    let row_length: usize = (columns * colors * bits).div_ceil(8);
    if row_length == 0 {
        return data.to_vec();
    }
    if predictor == 2 {
        return tiff_predictor(data, row_length, bytes_per_pixel);
    }
    png_predictor(data, row_length, bytes_per_pixel)
}

fn tiff_predictor(data: &[u8], row_length: usize, bpp: usize) -> Vec<u8> {
    let mut out: Vec<u8> = data.to_vec();
    for row in out.chunks_mut(row_length) {
        for index in bpp..row.len() {
            row[index] = row[index].wrapping_add(row[index - bpp]);
        }
    }
    out
}

fn png_predictor(data: &[u8], row_length: usize, bpp: usize) -> Vec<u8> {
    let stride: usize = row_length + 1;
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut previous: Vec<u8> = vec![0u8; row_length];
    for chunk in data.chunks(stride) {
        let Some((&filter, row_in)): Option<(&u8, &[u8])> = chunk.split_first() else {
            continue;
        };
        let mut row: Vec<u8> = vec![0u8; row_length];
        for index in 0..row_length {
            let raw: u8 = row_in.get(index).copied().unwrap_or(0);
            let left: u8 = if index >= bpp { row[index - bpp] } else { 0 };
            let up: u8 = previous[index];
            let up_left: u8 = if index >= bpp {
                previous[index - bpp]
            } else {
                0
            };
            row[index] = match filter {
                1 => raw.wrapping_add(left),
                2 => raw.wrapping_add(up),
                3 => raw.wrapping_add(u16::midpoint(u16::from(left), u16::from(up)) as u8),
                4 => raw.wrapping_add(paeth(left, up, up_left)),
                _ => raw,
            };
        }
        out.extend_from_slice(&row);
        previous = row;
    }
    out
}

fn paeth(left: u8, up: u8, up_left: u8) -> u8 {
    let base: i32 = i32::from(left) + i32::from(up) - i32::from(up_left);
    let distance_left: i32 = (base - i32::from(left)).abs();
    let distance_up: i32 = (base - i32::from(up)).abs();
    let distance_up_left: i32 = (base - i32::from(up_left)).abs();
    if distance_left <= distance_up && distance_left <= distance_up_left {
        left
    } else if distance_up <= distance_up_left {
        up
    } else {
        up_left
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_hex_decodes_with_terminator() {
        assert_eq!(ascii_hex_decode(b"48656c6c6f>trailing"), b"Hello");
    }

    #[test]
    fn ascii_hex_pads_odd_final_nibble() {
        assert_eq!(ascii_hex_decode(b"4>"), &[0x40]);
    }

    #[test]
    fn ascii85_decodes_classic_group() {
        let (out, capped): (Vec<u8>, bool) = ascii85_decode(b"9jqo^~>");
        assert!(!capped);
        assert_eq!(out, b"Man ");
    }

    #[test]
    fn ascii85_z_is_four_zero_bytes() {
        let (out, _): (Vec<u8>, bool) = ascii85_decode(b"z~>");
        assert_eq!(out, &[0, 0, 0, 0]);
    }

    #[test]
    fn run_length_literal_and_repeat() {
        let input: [u8; 7] = [0x02, b'A', b'B', b'C', 0xFE, b'Z', 0x80];
        let (out, _): (Vec<u8>, bool) = run_length_decode(&input);
        assert_eq!(out, b"ABCZZZ");
    }

    #[test]
    fn tiff_predictor_accumulates_row() {
        assert_eq!(tiff_predictor(&[1, 1, 1, 1], 4, 1), &[1, 2, 3, 4]);
    }

    #[test]
    fn png_up_predictor_reconstructs_rows() {
        let input: [u8; 8] = [0, 10, 20, 30, 2, 1, 1, 1];
        assert_eq!(png_predictor(&input, 3, 1), &[10, 20, 30, 11, 21, 31]);
    }

    fn deflate_zeros(len: usize) -> Option<Vec<u8>> {
        use std::io::Write;

        use flate2::Compression;
        use flate2::write::ZlibEncoder;

        let zeros: Vec<u8> = vec![0u8; len];
        let mut encoder: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&zeros).ok()?;
        encoder.finish().ok()
    }

    #[test]
    fn cumulative_output_cap_halts_further_streams() {
        let compressed: Vec<u8> = deflate_zeros(limits::MAX_STREAM_OUTPUT).unwrap_or_default();
        assert!(
            !compressed.is_empty(),
            "compressible fixture must produce input bytes"
        );

        let mut dict: PdfDict = PdfDict::new();
        dict.push(b"Filter".to_vec(), PdfObject::Name(b"FlateDecode".to_vec()));
        let stream: PdfStream = PdfStream {
            dict,
            raw: compressed,
        };

        let doc: PdfDocument = PdfDocument::default();
        let budgeted_streams: usize = limits::MAX_TOTAL_OUTPUT / limits::MAX_STREAM_OUTPUT;
        for _ in 0..budgeted_streams {
            let decoded: Decoded = decode_stream(&doc, &stream);
            assert_eq!(decoded.data.len(), limits::MAX_STREAM_OUTPUT);
        }
        assert_eq!(doc.total_decoded.get(), limits::MAX_TOTAL_OUTPUT);

        for _ in 0..4 {
            let decoded: Decoded = decode_stream(&doc, &stream);
            assert!(
                decoded.data.is_empty(),
                "stream past the cap must not decode"
            );
            assert!(decoded.capped);
        }
        assert_eq!(doc.total_decoded.get(), limits::MAX_TOTAL_OUTPUT);
    }
}
