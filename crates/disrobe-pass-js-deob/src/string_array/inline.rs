use std::collections::BTreeMap;
use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::sandbox::{DecoderProbe, DecoderSample, probe_decoder};

#[derive(Debug, Clone, Serialize)]
pub(super) struct InlineResult {
    pub(super) decoder_name: Option<String>,
    pub(super) call_sites_total: usize,
    pub(super) call_sites_inlined: usize,
    pub(super) probe: Option<DecoderProbe>,
    pub(super) rewritten_source: String,
}

pub(super) fn inline_decoder_calls(source: &str, array_id: &str) -> InlineResult {
    let Some((decoder_name, decoder_src, decoder_range)): Option<(String, String, Range<usize>)> =
        find_decoder(source, array_id)
    else {
        return empty_result(source);
    };

    let call_sites: Vec<CallSite> = find_call_sites(source, &decoder_name);
    let unique_indices: Vec<i64> = {
        let mut v: Vec<i64> = call_sites.iter().map(|c| c.index).collect();
        v.sort_unstable();
        v.dedup();
        v
    };

    let array_decl_re: Option<Regex> =
        Regex::new(r"(?ms)(var|let|const)\s+[\w$]+\s*=\s*\[[^\]]*\]\s*;").ok();
    let array_decl: String = array_decl_re
        .as_ref()
        .and_then(|re| re.find(source))
        .map_or_else(String::new, |m| m.as_str().to_owned());

    let probe: Option<DecoderProbe> = if !array_decl.is_empty() && !unique_indices.is_empty() {
        probe_decoder(&decoder_src, &array_decl, &decoder_name, &unique_indices)
    } else {
        None
    };

    let lookup: BTreeMap<i64, String> = probe.as_ref().map_or_else(BTreeMap::new, |p| {
        p.samples
            .iter()
            .map(|s: &DecoderSample| (s.index, s.decoded.clone()))
            .collect()
    });

    let mut rewritten: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut inlined: usize = 0;

    let mut events: Vec<Event> = Vec::with_capacity(call_sites.len() + 1);
    events.push(Event::DecoderDecl {
        range: decoder_range,
    });
    for site in &call_sites {
        events.push(Event::Call {
            range: site.range.clone(),
            index: site.index,
        });
    }
    events.sort_by_key(Event::start);

    for event in events {
        let (start, end): (usize, usize) = event.range();
        if start < cursor {
            continue;
        }
        rewritten.push_str(&source[cursor..start]);
        match event {
            Event::DecoderDecl { .. } => {}
            Event::Call { index, .. } => {
                if let Some(decoded) = lookup.get(&index) {
                    rewritten.push_str(&js_quote(decoded));
                    inlined += 1;
                } else {
                    rewritten.push_str(&source[start..end]);
                }
            }
        }
        cursor = end;
    }
    rewritten.push_str(&source[cursor..]);

    InlineResult {
        decoder_name: Some(decoder_name),
        call_sites_total: call_sites.len(),
        call_sites_inlined: inlined,
        probe,
        rewritten_source: rewritten,
    }
}

fn empty_result(source: &str) -> InlineResult {
    InlineResult {
        decoder_name: None,
        call_sites_total: 0,
        call_sites_inlined: 0,
        probe: None,
        rewritten_source: source.to_owned(),
    }
}

#[derive(Debug, Clone)]
struct CallSite {
    range: Range<usize>,
    index: i64,
}

#[derive(Debug, Clone)]
enum Event {
    DecoderDecl { range: Range<usize> },
    Call { range: Range<usize>, index: i64 },
}

impl Event {
    const fn start(&self) -> usize {
        match self {
            Self::DecoderDecl { range } | Self::Call { range, .. } => range.start,
        }
    }
    const fn range(&self) -> (usize, usize) {
        match self {
            Self::DecoderDecl { range } | Self::Call { range, .. } => (range.start, range.end),
        }
    }
}

fn find_decoder(source: &str, array_id: &str) -> Option<(String, String, Range<usize>)> {
    let needle_id: String = regex::escape(array_id);
    let pattern: String = format!(
        r"(?ms)(?:var|let|const)\s+([\w$]+)\s*=\s*function\s*\([^)]*\)\s*\{{\s*(?:var\s+[\w$]+\s*=\s*{needle_id}\s*;\s*)?[^}}]*{needle_id}\s*\[[^\]]+\][^}}]*\}}\s*;",
    );
    if let Ok(re) = Regex::new(&pattern)
        && let Some(cap) = re.captures(source)
    {
        let name: String = cap.get(1)?.as_str().to_owned();
        let whole: regex::Match<'_> = cap.get(0)?;
        return Some((name, whole.as_str().to_owned(), whole.start()..whole.end()));
    }
    let pattern2: String = format!(
        r"(?ms)function\s+([\w$]+)\s*\([^)]*\)\s*\{{\s*(?:var\s+[\w$]+\s*=\s*{needle_id}\s*;\s*)?[^}}]*{needle_id}\s*\[[^\]]+\][^}}]*\}}",
    );
    let re: Regex = Regex::new(&pattern2).ok()?;
    let cap: regex::Captures<'_> = re.captures(source)?;
    let name: String = cap.get(1)?.as_str().to_owned();
    let whole: regex::Match<'_> = cap.get(0)?;
    Some((name, whole.as_str().to_owned(), whole.start()..whole.end()))
}

fn find_call_sites(source: &str, decoder_name: &str) -> Vec<CallSite> {
    let escaped: String = regex::escape(decoder_name);
    let pattern: String = format!(r"\b{escaped}\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)");
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut out: Vec<CallSite> = Vec::new();
    for cap in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(arg): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        if let Some(idx) = parse_int(arg.as_str()) {
            out.push(CallSite {
                range: whole.start()..whole.end(),
                index: idx,
            });
        }
    }
    out
}

fn parse_int(s: &str) -> Option<i64> {
    let Some(hex): Option<&str> = s.strip_prefix("0x").or_else(|| s.strip_prefix("-0x")) else {
        return s.parse::<i64>().ok();
    };
    let sign: i64 = if s.starts_with('-') { -1 } else { 1 };
    i64::from_str_radix(hex, 16).ok().map(|v| sign * v)
}

fn js_quote(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn finds_simple_decoder() {
        let src: &str =
            "var _0xabcd = ['x'];\nvar _0xdec = function (i) { return _0xabcd[i - 0]; };\nfoo();";
        let Some((name, _src, _r)): Option<(String, String, Range<usize>)> =
            find_decoder(src, "_0xabcd")
        else {
            panic!("decoder must be found in test fixture");
        };
        assert_eq!(name, "_0xdec");
    }

    #[test]
    fn finds_call_sites_with_hex_index() {
        let src: &str = "_dec(0x0); _dec(0x1); _dec(2);";
        let sites: Vec<CallSite> = find_call_sites(src, "_dec");
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0].index, 0);
        assert_eq!(sites[1].index, 1);
        assert_eq!(sites[2].index, 2);
    }

    #[test]
    fn end_to_end_inline() {
        let src: &str = r"var _0xab = ['hi', 'world'];
var _0xdec = function (i) { return _0xab[i]; };
console.log(_0xdec(0x0), _0xdec(0x1));
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.decoder_name.as_deref(), Some("_0xdec"));
        assert_eq!(result.call_sites_total, 2);
        assert!(
            result.call_sites_inlined >= 1,
            "at least one site should inline"
        );
        assert!(
            result.rewritten_source.contains("'hi'") || result.rewritten_source.contains("'world'"),
            "expected at least one decoded literal; got: {}",
            result.rewritten_source
        );
        assert!(
            !result.rewritten_source.contains("var _0xdec"),
            "decoder declaration should be removed: {}",
            result.rewritten_source
        );
    }
}
