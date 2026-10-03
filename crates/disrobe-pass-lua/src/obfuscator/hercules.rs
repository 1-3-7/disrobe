use crate::error::{Error, Result};
use crate::obfuscator::hercules_recover::{SourceRecovery, function_literal_count, recover_source};
use crate::obfuscator::vm_devirt::{devirt_to_peel, extract_embedded_payload};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};
use crate::reader::{LuaProto, read_auto};

const WATERMARK_MARKERS: &[&[u8]] = &[
    b"Obfuscated by Hercules",
    b"hercules-obfuscator.xyz",
    b"hercules-obfuscator",
];

const MAX_LOADER_DEPTH: usize = 16;
const MIN_HEX_LOADER_LEN: usize = 16;

#[must_use]
pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut markers: Vec<String> = Vec::new();
    for m in WATERMARK_MARKERS {
        if disrobe_core::byte_search::contains(src, m) {
            markers.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    let watermarked: bool = !markers.is_empty();

    let loader: Option<HexSubtractLoader> = find_hex_subtract_loader(src);
    if let Some(ref l) = loader {
        markers.push(format!(
            "hex-subtract self-decrypt loader ({} hex digits, key {})",
            l.hex.len(),
            l.key
        ));
    }

    if markers.is_empty() {
        return None;
    }

    let confidence: u8 = match (watermarked, loader.is_some()) {
        (true, true) => 97,
        (true, false) => 90,
        (false, true) => 70,
        (false, false) => 0,
    };
    let variant: &'static str = if loader.is_some() {
        "hex-subtract-loader+bytecode-vm"
    } else {
        "watermark-only"
    };
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::Hercules,
        variant: Some(variant.to_owned()),
        confidence,
        markers,
    })
}

#[derive(Debug, Clone)]
struct HexSubtractLoader {
    hex: String,
    key: u16,
}

fn find_hex_subtract_loader(src: &[u8]) -> Option<HexSubtractLoader> {
    let mut quote_open: usize = 0;
    while quote_open < src.len() {
        let rel: usize = disrobe_core::byte_search::find(&src[quote_open..], b"\"")?;
        let here: usize = quote_open + rel;
        let hex_start: usize = here + 1;
        let mut cursor: usize = hex_start;
        while cursor < src.len() && src[cursor].is_ascii_hexdigit() {
            cursor += 1;
        }
        let hex_len: usize = cursor - hex_start;
        if hex_len >= MIN_HEX_LOADER_LEN
            && hex_len.is_multiple_of(2)
            && src.get(cursor) == Some(&b'"')
            && let Ok(hex) = core::str::from_utf8(&src[hex_start..cursor])
            && let Some(key) = parse_trailing_key(&src[cursor + 1..])
        {
            return Some(HexSubtractLoader {
                hex: hex.to_owned(),
                key,
            });
        }
        quote_open = here + 1;
    }
    None
}

fn parse_trailing_key(after_quote: &[u8]) -> Option<u16> {
    let mut idx: usize = 0;
    while idx < after_quote.len() && matches!(after_quote[idx], b'"' | b',' | b' ') {
        idx += 1;
    }
    let digits_start: usize = idx;
    while idx < after_quote.len() && after_quote[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == digits_start {
        return None;
    }
    let rest: &[u8] = &after_quote[idx..];
    let mut tail: usize = 0;
    while tail < rest.len() && matches!(rest[tail], b' ' | b',') {
        tail += 1;
    }
    if rest.get(tail) != Some(&b'{') || rest.get(tail + 1) != Some(&b'}') {
        return None;
    }
    core::str::from_utf8(&after_quote[digits_start..idx])
        .ok()
        .and_then(|s: &str| s.parse::<u16>().ok())
}

fn decode_hex_subtract(loader: &HexSubtractLoader) -> Option<Vec<u8>> {
    let hex: &[u8] = loader.hex.as_bytes();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let key: i32 = i32::from(loader.key);
    let mut out: Vec<u8> = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks_exact(2) {
        let hi: u8 = hex_nibble(pair[0])?;
        let lo: u8 = hex_nibble(pair[1])?;
        let byte: i32 = i32::from((hi << 4) | lo);
        out.push((((byte - key) % 256 + 256) % 256) as u8);
    }
    Some(out)
}

#[must_use]
const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("Hercules"));
    }

    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let embedded_payload: Option<Vec<u8>> = extract_embedded_payload(&text);
    if let Some(payload) = embedded_payload {
        return devirt_to_peel(src, &text, &payload, "hercules");
    }

    let mut current: Vec<u8> = src.to_vec();
    let mut passes_run: Vec<String> = Vec::new();
    let mut layers_decoded: usize = 0;

    for _ in 0..MAX_LOADER_DEPTH {
        let Some(loader): Option<HexSubtractLoader> = find_hex_subtract_loader(&current) else {
            break;
        };
        let Some(decoded): Option<Vec<u8>> = decode_hex_subtract(&loader) else {
            break;
        };
        current = decoded;
        layers_decoded += 1;
        passes_run.push(format!(
            "hercules-hex-subtract-loader-decode (layer {layers_decoded}, key {})",
            loader.key
        ));
    }

    let source: String = match next_source_layer(&current, layers_decoded) {
        Ok((source, pass)) => {
            passes_run.extend(pass);
            source
        }
        Err(reason) => {
            return Ok(PeelResult {
                deobfuscated: current,
                passes_run,
                residual_markers: vec![reason],
                recovered_strings: Vec::new(),
                fully_recovered: false,
            });
        }
    };

    let recovery: SourceRecovery = recover_source(&source);
    passes_run.extend(recovery.passes);
    Ok(PeelResult {
        deobfuscated: recovery.source.into_bytes(),
        passes_run,
        fully_recovered: recovery.residual.is_empty(),
        residual_markers: recovery.residual,
        recovered_strings: recovery.strings,
    })
}

fn next_source_layer(
    current: &[u8],
    layers_decoded: usize,
) -> core::result::Result<(String, Option<String>), String> {
    if layers_decoded == 0 {
        return String::from_utf8(current.to_vec())
            .map(|source: String| (source, None))
            .map_err(|_: std::string::FromUtf8Error| {
                "hercules: source is not UTF-8, so its string literals cannot be rewritten byte for byte".to_owned()
            });
    }
    let Ok(chunk) = read_auto(current) else {
        return String::from_utf8(current.to_vec())
            .map(|source: String| (source, Some("hercules-loader-source-layer".to_owned())))
            .map_err(|_: std::string::FromUtf8Error| {
                format!(
                    "hercules: loader decrypted to a {}-byte payload that is neither Lua bytecode nor UTF-8 source",
                    current.len()
                )
            });
    };
    let Some(source) = chunk.main.source.as_deref() else {
        return Err(
            "hercules: loader decrypted to stripped Lua bytecode with no embedded source; the bytecode is not lifted by this pass"
                .to_owned(),
        );
    };
    if source.starts_with(['=', '@']) || source.contains(char::REPLACEMENT_CHARACTER) {
        return Err(
            "hercules: loader bytecode names its source instead of embedding it; the bytecode is not lifted by this pass"
                .to_owned(),
        );
    }
    let protos: usize = count_nested_protos(&chunk.main);
    match function_literal_count(source) {
        Ok(literals) if literals == protos => Ok((
            source.to_owned(),
            Some("hercules-bytecode-source-field-extract".to_owned()),
        )),
        Ok(literals) => Err(format!(
            "hercules: the bytecode's embedded source declares {literals} function(s) but the bytecode carries {protos}, so the source field is not trusted as the compiled program"
        )),
        Err(err) => Err(format!(
            "hercules: the bytecode's embedded source does not parse ({err})"
        )),
    }
}

fn count_nested_protos(proto: &LuaProto) -> usize {
    proto
        .protos
        .iter()
        .map(|sub: &LuaProto| 1 + count_nested_protos(sub))
        .sum()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{ObfuscatorDetection, detect, find_hex_subtract_loader};

    #[test]
    fn quote_scan_survives_degenerate_input() {
        assert!(find_hex_subtract_loader(b"").is_none());
        assert!(find_hex_subtract_loader(b"\"").is_none());
        assert!(find_hex_subtract_loader(b"local a = \"\"").is_none());
        assert!(find_hex_subtract_loader(b"local a = \"deadbeef\"").is_none());
        assert_eq!(
            disrobe_core::byte_search::find(b"local a = \"\"", b""),
            None
        );
    }

    #[test]
    fn watermark_only_source_detects_without_loader() {
        let detection: ObfuscatorDetection =
            detect(b"-- Obfuscated by Hercules\nprint(1)\n").expect("detection");
        assert_eq!(detection.variant.as_deref(), Some("watermark-only"));
        assert_eq!(detection.confidence, 90);
        assert!(detect(b"print(1)\n").is_none());
    }
}
