use std::collections::BTreeMap;
use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::{
    decode_string_literal_at, find_paren_close, scan_balanced_brace, scan_balanced_bracket,
    skip_whitespace,
};

#[derive(Debug, Clone, Serialize)]
pub struct StringConcealResult {
    pub accessor_id: Option<String>,
    pub pool_size: usize,
    pub call_sites_decoded: usize,
    pub runtime_keyed: bool,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_string_conceal(source: &str) -> StringConcealResult {
    let decoders: Vec<Decoder> = find_decoders(source);
    if decoders.is_empty() {
        return passthrough(source, None, false);
    }

    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut first_accessor: Option<String> = None;
    let mut total_pool: usize = 0;
    let mut decoded_count: usize = 0;
    let mut any_runtime_keyed: bool = false;

    for decoder in &decoders {
        let Some(accessor): Option<Accessor> = find_accessor(source, &decoder.fn_name) else {
            continue;
        };
        let Some(pool): Option<Vec<String>> = find_pool(source, &accessor.array_id) else {
            continue;
        };
        if first_accessor.is_none() {
            first_accessor = Some(accessor.fn_name.clone());
        }
        total_pool += pool.len();
        let Some(table): Option<&String> =
            decoder.table.as_ref().filter(|_| !decoder.runtime_keyed)
        else {
            any_runtime_keyed = true;
            continue;
        };

        let mut decoded_cache: BTreeMap<usize, Option<String>> = BTreeMap::new();
        for site in find_call_sites(source, &accessor.fn_name) {
            let entry: &Option<String> = decoded_cache.entry(site.index).or_insert_with(|| {
                pool.get(site.index)
                    .and_then(|raw: &String| base91_then_utf8(raw, table))
            });
            let Some(value) = entry.as_ref() else {
                continue;
            };
            edits.push((site.range, Some(render_string_literal(value))));
            decoded_count += 1;
        }
    }

    if edits.is_empty() {
        return StringConcealResult {
            accessor_id: first_accessor,
            pool_size: total_pool,
            call_sites_decoded: 0,
            runtime_keyed: any_runtime_keyed,
            rewritten_source: source.to_owned(),
        };
    }
    let (rewritten, applied): (String, usize) =
        super::scanner::apply_splice_edits(source, &mut edits);
    StringConcealResult {
        accessor_id: first_accessor,
        pool_size: total_pool,
        call_sites_decoded: applied.min(decoded_count),
        runtime_keyed: any_runtime_keyed,
        rewritten_source: rewritten,
    }
}

fn passthrough(
    source: &str,
    accessor_id: Option<String>,
    runtime_keyed: bool,
) -> StringConcealResult {
    StringConcealResult {
        accessor_id,
        pool_size: 0,
        call_sites_decoded: 0,
        runtime_keyed,
        rewritten_source: source.to_owned(),
    }
}

#[derive(Debug, Clone)]
struct Decoder {
    fn_name: String,
    table: Option<String>,
    runtime_keyed: bool,
}

#[derive(Debug, Clone)]
struct Accessor {
    fn_name: String,
    array_id: String,
}

#[derive(Debug, Clone)]
struct CallSite {
    range: Range<usize>,
    index: usize,
}

fn find_decoders(source: &str) -> Vec<Decoder> {
    let header_re: Regex =
        match Regex::new(r"(?ms)function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{")
        {
            Ok(re) => re,
            Err(_) => return Vec::new(),
        };
    let mut out: Vec<Decoder> = Vec::new();
    for cap in header_re.captures_iter(source) {
        let Some(name): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let body_open: usize = whole.end() - 1;
        let Some(body_close): Option<usize> = scan_balanced_brace(source, body_open + 1) else {
            continue;
        };
        let Some(body): Option<&str> = source.get(body_open + 1..body_close) else {
            continue;
        };
        if !is_base91_decoder(body) {
            continue;
        }
        let table: Option<String> = extract_table_literal(body);
        let runtime_keyed: bool = table.is_none() || table_is_runtime_derived(body);
        out.push(Decoder {
            fn_name: name.as_str().to_owned(),
            table,
            runtime_keyed,
        });
    }
    out
}

fn extract_table_literal(body: &str) -> Option<String> {
    let re: Regex = Regex::new(r#"(?ms)\btable\s*=\s*""#).ok()?;
    let mat: regex::Match<'_> = re.find(body)?;
    let quote_pos: usize = mat.end() - 1;
    let (literal, _): (String, usize) = decode_string_literal_at(body.as_bytes(), quote_pos)?;
    if literal.chars().count() == 91 {
        Some(literal)
    } else {
        None
    }
}

fn is_base91_decoder(body: &str) -> bool {
    body.contains("indexOf") && (body.contains("* 91") || body.contains("*91"))
}

fn table_is_runtime_derived(body: &str) -> bool {
    let dynamic_re: Regex = match Regex::new(
        r"(?ms)\btable\s*=\s*[A-Za-z_$][\w$.]*\s*\(|\btable\s*\.\s*split|\btable\s*=\s*table\s*\[",
    ) {
        Ok(re) => re,
        Err(_) => return false,
    };
    dynamic_re.is_match(body)
}

fn find_accessor(source: &str, decoder_fn: &str) -> Option<Accessor> {
    let escaped: String = regex::escape(decoder_fn);
    let header_re: Regex =
        Regex::new(r"(?ms)function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{")
            .ok()?;
    let array_probe: Regex = Regex::new(&format!(
        r"(?ms){escaped}\s*\(\s*([A-Za-z_$][\w$]*)\s*\[\s*[A-Za-z_$][\w$]*\s*\]\s*\)"
    ))
    .ok()?;
    for cap in header_re.captures_iter(source) {
        let Some(name): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        if name.as_str() == decoder_fn {
            continue;
        }
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let body_open: usize = whole.end() - 1;
        let Some(body_close): Option<usize> = scan_balanced_brace(source, body_open + 1) else {
            continue;
        };
        let Some(body): Option<&str> = source.get(body_open + 1..body_close) else {
            continue;
        };
        let Some(probe): Option<regex::Captures<'_>> = array_probe.captures(body) else {
            continue;
        };
        let Some(array_id): Option<String> = probe
            .get(1)
            .map(|m: regex::Match<'_>| m.as_str().to_owned())
        else {
            continue;
        };
        return Some(Accessor {
            fn_name: name.as_str().to_owned(),
            array_id,
        });
    }
    None
}

fn find_pool(source: &str, array_id: &str) -> Option<Vec<String>> {
    let escaped: String = regex::escape(array_id);
    let re: Regex = Regex::new(&format!(r"(?ms)(?:var|let|const)\s+{escaped}\s*=\s*\[")).ok()?;
    let mat: regex::Match<'_> = re.find(source)?;
    let open_bracket: usize = mat.end() - 1;
    let close_bracket: usize = scan_balanced_bracket(source, open_bracket + 1)?;
    let inner: &str = source.get(open_bracket + 1..close_bracket)?;
    parse_string_array(inner)
}

fn parse_string_array(inner: &str) -> Option<Vec<String>> {
    let bytes: &[u8] = inner.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        i = skip_whitespace(bytes, i);
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b',' {
            i += 1;
            continue;
        }
        if !matches!(bytes[i], b'"' | b'\'') {
            return None;
        }
        let (literal, next): (String, usize) = decode_string_literal_at(bytes, i)?;
        out.push(literal);
        i = next;
    }
    if out.is_empty() { None } else { Some(out) }
}

fn find_call_sites(source: &str, accessor_fn: &str) -> Vec<CallSite> {
    let escaped: String = regex::escape(accessor_fn);
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(&format!(r"(?ms)\b{escaped}\s*\(\s*(-?\d+)\s*\)"))
    else {
        return Vec::new();
    };
    let mut out: Vec<CallSite> = Vec::new();
    for cap in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(index): Option<usize> = cap
            .get(1)
            .and_then(|m: regex::Match<'_>| m.as_str().parse::<usize>().ok())
        else {
            continue;
        };
        out.push(CallSite {
            range: whole.start()..whole.end(),
            index,
        });
    }
    out
}

fn base91_then_utf8(encoded: &str, table: &str) -> Option<String> {
    let bytes: Vec<u8> = base91_decode(encoded, table);
    String::from_utf8(bytes).ok()
}

fn base91_decode(encoded: &str, table: &str) -> Vec<u8> {
    let lookup: BTreeMap<char, i64> = table
        .chars()
        .enumerate()
        .map(|(idx, ch): (usize, char)| (ch, idx as i64))
        .collect();
    let mut out: Vec<u8> = Vec::new();
    let mut b: i64 = 0;
    let mut n: i64 = 0;
    let mut v: i64 = -1;
    for ch in encoded.chars() {
        let Some(&p): Option<&i64> = lookup.get(&ch) else {
            continue;
        };
        if v < 0 {
            v = p;
        } else {
            v += p * 91;
            b |= v << n;
            n += if (v & 8191) > 88 { 13 } else { 14 };
            loop {
                out.push((b & 255) as u8);
                b >>= 8;
                n -= 8;
                if n <= 7 {
                    break;
                }
            }
            v = -1;
        }
    }
    if v > -1 {
        out.push(((b | (v << n)) & 255) as u8);
    }
    out
}

fn render_string_literal(value: &str) -> String {
    let needs_double: bool = value.contains('"');
    let needs_single: bool = value.contains('\'');
    let quote: char = if needs_double && !needs_single {
        '\''
    } else {
        '"'
    };
    let mut out: String = String::with_capacity(value.len() + 2);
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[allow(dead_code)]
fn unused_paren(bytes: &[u8], start: usize) -> Option<usize> {
    find_paren_close(bytes, start)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

    fn b91_encode(data: &[u8], table: &str) -> String {
        let alphabet: Vec<char> = table.chars().collect();
        let mut out: String = String::new();
        let mut b: i64 = 0;
        let mut n: i64 = 0;
        for &byte in data {
            b |= (byte as i64) << n;
            n += 8;
            if n > 13 {
                let mut v: i64 = b & 8191;
                if v > 88 {
                    b >>= 13;
                    n -= 13;
                } else {
                    v = b & 16383;
                    b >>= 14;
                    n -= 14;
                }
                out.push(alphabet[(v % 91) as usize]);
                out.push(alphabet[(v / 91) as usize]);
            }
        }
        if n > 0 {
            out.push(alphabet[(b % 91) as usize]);
            if n > 7 || b > 90 {
                out.push(alphabet[(b / 91) as usize]);
            }
        }
        out
    }

    #[test]
    fn base91_roundtrips_ascii() {
        let original: &[u8] = b"hello world";
        let encoded: String = b91_encode(original, TABLE);
        let decoded: Vec<u8> = base91_decode(&encoded, TABLE);
        assert_eq!(decoded, original);
    }

    #[test]
    fn base91_roundtrips_utf8() {
        let original: &str = "gammaé-π";
        let encoded: String = b91_encode(original.as_bytes(), TABLE);
        let decoded: String = base91_then_utf8(&encoded, TABLE).expect("decode utf8");
        assert_eq!(decoded, original);
    }

    #[test]
    fn parses_string_pool() {
        let pool: Vec<String> = parse_string_array(r#""abc", "de\"f", 'gh'"#).expect("parse pool");
        assert_eq!(pool, vec!["abc", "de\"f", "gh"]);
    }

    #[test]
    fn finds_call_site_indices() {
        let sites: Vec<CallSite> = find_call_sites("x = _dec(7) + _dec(12);", "_dec");
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].index, 7);
        assert_eq!(sites[1].index, 12);
    }

    fn build_conceal_source(words: &[&str]) -> String {
        let pool: String = words
            .iter()
            .map(|w: &&str| format!("\"{}\"", b91_encode(w.as_bytes(), TABLE)))
            .collect::<Vec<String>>()
            .join(", ");
        let table_escaped: String = TABLE.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "function dec_decode(str){{var table=\"{table_escaped}\";var raw=\"\"+(str||\"\");var len=raw.length;var ret=[];var b=0;var n=0;var v=-1;for(var i=0;i<len;i++){{var p=table.indexOf(raw[i]);if(p===-1)continue;if(v<0){{v=p}}else{{v+=p*91;b|=v<<n;n+=(v&8191)>88?13:14;do{{ret.push(b&255);b>>=8;n-=8}}while(n>7);v=-1}}}}if(v>-1){{ret.push((b|v<<n)&255)}}return String.fromCharCode.apply(null,ret)}}\nfunction pick(index){{return dec_decode(pool[index])}}\nvar pool=[{pool}];\nconsole.log(pick(0), pick(1));"
        )
    }

    #[test]
    fn decodes_static_base91_pool_end_to_end() {
        let src: String = build_conceal_source(&["greeting", "payload"]);
        let r: StringConcealResult = reverse_string_conceal(&src);
        assert!(!r.runtime_keyed);
        assert_eq!(r.pool_size, 2);
        assert_eq!(r.call_sites_decoded, 2);
        assert!(
            r.rewritten_source.contains("\"greeting\""),
            "decoded literal must reappear: {}",
            r.rewritten_source
        );
        assert!(r.rewritten_source.contains("\"payload\""));
        assert!(!r.rewritten_source.contains("pick(0)"));
    }

    fn build_named_decoder(decoder: &str, accessor: &str, array: &str, words: &[&str]) -> String {
        let pool: String = words
            .iter()
            .map(|w: &&str| format!("\"{}\"", b91_encode(w.as_bytes(), TABLE)))
            .collect::<Vec<String>>()
            .join(", ");
        let table_escaped: String = TABLE.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "function {decoder}(str){{var table=\"{table_escaped}\";var raw=\"\"+(str||\"\");var len=raw.length;var ret=[];var b=0;var n=0;var v=-1;for(var i=0;i<len;i++){{var p=table.indexOf(raw[i]);if(p===-1)continue;if(v<0){{v=p}}else{{v+=p*91;b|=v<<n;n+=(v&8191)>88?13:14;do{{ret.push(b&255);b>>=8;n-=8}}while(n>7);v=-1}}}}if(v>-1){{ret.push((b|v<<n)&255)}}return String.fromCharCode.apply(null,ret)}}\nfunction {accessor}(index){{return {decoder}({array}[index])}}\nvar {array}=[{pool}];"
        )
    }

    #[test]
    fn decodes_multiple_independent_pools() {
        let a: String = build_named_decoder("d1_decode", "d1", "pool1", &["alpha", "beta"]);
        let b: String = build_named_decoder("d2_decode", "d2", "pool2", &["gamma", "delta"]);
        let src: String = format!("{a}\n{b}\nconsole.log(d1(0), d1(1), d2(0), d2(1));");
        let r: StringConcealResult = reverse_string_conceal(&src);
        assert_eq!(r.pool_size, 4, "both pools must be counted");
        assert_eq!(r.call_sites_decoded, 4, "all four call sites must decode");
        for literal in ["\"alpha\"", "\"beta\"", "\"gamma\"", "\"delta\""] {
            assert!(
                r.rewritten_source.contains(literal),
                "missing decoded literal {literal}: {}",
                r.rewritten_source
            );
        }
        assert!(!r.rewritten_source.contains("d1(0)") && !r.rewritten_source.contains("d2(1)"));
    }

    #[test]
    fn runtime_derived_table_is_walled() {
        let src: String = build_conceal_source(&["secret"]).replace(
            "var table=\"",
            "var table=globalThis.__rt_key();var __unused=\"",
        );
        let r: StringConcealResult = reverse_string_conceal(&src);
        assert!(
            r.runtime_keyed,
            "a table assigned from a runtime call must be flagged runtime-keyed, not decoded"
        );
        assert_eq!(
            r.call_sites_decoded, 0,
            "no literal may be fabricated when the key is not statically present"
        );
        assert_eq!(r.rewritten_source, src);
    }
}
