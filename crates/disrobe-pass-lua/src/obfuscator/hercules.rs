use crate::error::{Error, Result};
use crate::obfuscator::vm_devirt::{devirt_to_peel, extract_embedded_payload};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};
use crate::reader::{LuaConstant, LuaProto, read_auto};

const WATERMARK_MARKERS: &[&[u8]] = &[
    b"Obfuscated by Hercules",
    b"hercules-obfuscator.xyz",
    b"hercules-obfuscator",
];

const MAX_LOADER_DEPTH: usize = 16;
const MIN_HEX_LOADER_LEN: usize = 16;
const MIN_INNER_LAYER_LEN: usize = 24;

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
        let rel: usize = find_subslice(&src[quote_open..], b"\"")?;
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
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

    if layers_decoded == 0 {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "hercules: watermark present but no static hex-subtract self-decrypt loader could be parsed from this artifact".to_owned(),
            ],
        ));
    }

    let mut recovered_strings: Vec<String> = Vec::new();
    let mut residual_markers: Vec<String> = Vec::new();
    let mut deob: Vec<u8> = current.clone();

    if let Ok(chunk) = read_auto(&current) {
        let mut pool: Vec<String> = Vec::new();
        collect_string_constants(&chunk.main, &mut pool);
        if pool.is_empty() {
            residual_markers.push(
                "hercules: loader decrypted to a Lua bytecode chunk with no extractable string constant".to_owned(),
            );
        } else {
            passes_run.push("hercules-embedded-bytecode-constant-extract".to_owned());
            let inner: Option<String> = pool
                .iter()
                .filter(|s: &&String| s.len() >= MIN_INNER_LAYER_LEN)
                .max_by_key(|s: &&String| s.len())
                .cloned();
            if let Some(inner_layer) = inner {
                deob = render_recovered(&inner_layer);
                recovered_strings.push(inner_layer);
            } else {
                recovered_strings.extend(pool);
            }
            residual_markers.push(format!(
                "hercules: extracted {} string constant(s) ({} bytes largest) from the embedded Lua bytecode chunk after the outer loader decrypt; this constant is the bytecode-encoder/StringToExpressions next layer, not yet cleartext source",
                recovered_strings.len(),
                recovered_strings.iter().map(String::len).max().unwrap_or(0)
            ));
        }
    } else {
        residual_markers.push(format!(
            "hercules: loader decrypted to a {}-byte non-bytecode payload (further source-form layer)",
            current.len()
        ));
    }

    residual_markers.push(
        "hercules: the StringToExpressions arithmetic-string encoding, variable renaming, opaque predicates and the inner bytecode VM (VMGenerator) are not lifted back to original Lua by this pass"
            .to_owned(),
    );

    Ok(PeelResult {
        deobfuscated: deob,
        passes_run,
        residual_markers,
        recovered_strings,
        fully_recovered: false,
    })
}

fn collect_string_constants(proto: &LuaProto, out: &mut Vec<String>) {
    for c in &proto.constants {
        if let LuaConstant::Str(s) = c {
            out.push(s.clone());
        }
    }
    for sub in &proto.protos {
        collect_string_constants(sub, out);
    }
}

fn render_recovered(inner_layer: &str) -> Vec<u8> {
    let mut out: String = String::with_capacity(inner_layer.len() + 96);
    out.push_str("local HERCULES_EMBEDDED_NEXT_LAYER = [==[\n");
    out.push_str(inner_layer);
    out.push_str("\n]==]\n");
    out.into_bytes()
}
