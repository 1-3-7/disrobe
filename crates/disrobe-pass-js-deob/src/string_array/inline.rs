use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::sandbox::{
    DecoderProbe, DecoderSample, MAX_PROBE_EXPRESSIONS, ProbeRefusal, probe_decoder,
};
use super::{executable_code_exclusions, resolved_reference_starts};
use crate::scan_utils::find_paren_close;

#[derive(Debug, Clone, Serialize)]
pub(super) struct InlineResult {
    pub(super) decoder_name: Option<String>,
    pub(super) call_sites_total: usize,
    pub(super) call_sites_inlined: usize,
    pub(super) probe: Option<DecoderProbe>,
    pub(super) probe_refusal: Option<ProbeRefusal>,
    pub(super) rewritten_source: String,
}

pub(super) fn inline_decoder_calls(source: &str, array_id: &str) -> InlineResult {
    let Some((decoder_name, decoder_src, decoder_range)): Option<(String, String, Range<usize>)> =
        find_decoder(source, array_id)
    else {
        return empty_result(source);
    };

    let inventory: CallInventory = match find_call_sites(source, &decoder_name, &decoder_range) {
        Ok(inventory) => inventory,
        Err(refusal) => {
            return InlineResult {
                decoder_name: Some(decoder_name),
                call_sites_total: 0,
                call_sites_inlined: 0,
                probe: None,
                probe_refusal: Some(refusal),
                rewritten_source: source.to_owned(),
            };
        }
    };
    let call_sites: Vec<CallSite> = inventory.call_sites;
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

    let (probe, probe_refusal): (Option<DecoderProbe>, Option<ProbeRefusal>) =
        if !array_decl.is_empty() && !unique_indices.is_empty() {
            match probe_decoder(&decoder_src, &array_decl, &decoder_name, &unique_indices) {
                Ok(probe) => (Some(probe), None),
                Err(refusal) => (None, Some(refusal)),
            }
        } else {
            (None, None)
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
    let every_call_decoded: bool = !inventory.has_unresolved_use
        && call_sites
            .iter()
            .all(|site: &CallSite| lookup.contains_key(&site.index));
    if every_call_decoded {
        events.push(Event::DecoderDecl {
            range: decoder_range,
        });
    }
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
        probe_refusal,
        rewritten_source: rewritten,
    }
}

fn empty_result(source: &str) -> InlineResult {
    InlineResult {
        decoder_name: None,
        call_sites_total: 0,
        call_sites_inlined: 0,
        probe: None,
        probe_refusal: None,
        rewritten_source: source.to_owned(),
    }
}

#[derive(Debug, Clone)]
struct CallSite {
    range: Range<usize>,
    index: i64,
}

#[derive(Debug, Clone)]
struct CallInventory {
    call_sites: Vec<CallSite>,
    has_unresolved_use: bool,
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

fn find_call_sites(
    source: &str,
    decoder_name: &str,
    decoder_range: &Range<usize>,
) -> Result<CallInventory, ProbeRefusal> {
    let escaped: String = regex::escape(decoder_name);
    let pattern: String = escaped;
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
        return Ok(CallInventory {
            call_sites: Vec::new(),
            has_unresolved_use: true,
        });
    };
    let non_code: Vec<Range<usize>> = executable_code_exclusions(source)?;
    let bytes: &[u8] = source.as_bytes();
    let mut identifiers: Vec<Range<usize>> = Vec::new();
    let mut non_code_index: usize = 0;
    for whole in re.find_iter(source) {
        while non_code_index < non_code.len() && non_code[non_code_index].end <= whole.start() {
            non_code_index += 1;
        }
        if non_code
            .get(non_code_index)
            .is_some_and(|range: &Range<usize>| range.start <= whole.start())
            || (decoder_range.start <= whole.start() && whole.start() < decoder_range.end)
            || !identifier_is_bounded(bytes, whole.start(), whole.end())
        {
            continue;
        }
        if identifiers.len() == MAX_PROBE_EXPRESSIONS {
            return Err(ProbeRefusal::BoundExceeded);
        }
        identifiers
            .try_reserve(1)
            .map_err(|_| ProbeRefusal::BoundExceeded)?;
        identifiers.push(whole.start()..whole.end());
    }
    let Some(resolved_starts): Option<std::collections::BTreeSet<usize>> =
        resolved_reference_starts(source, &[decoder_name], std::slice::from_ref(decoder_range))
    else {
        return Ok(CallInventory {
            call_sites: Vec::new(),
            has_unresolved_use: true,
        });
    };
    let mut out: Vec<CallSite> = Vec::new();
    out.try_reserve(identifiers.len())
        .map_err(|_| ProbeRefusal::BoundExceeded)?;
    let scanned_starts: BTreeSet<usize> = identifiers
        .iter()
        .map(|identifier: &Range<usize>| identifier.start)
        .collect();
    let mut has_unresolved_use: bool = resolved_starts
        .iter()
        .any(|start: &usize| !decoder_range.contains(start) && !scanned_starts.contains(start));
    for whole in identifiers {
        if is_property_access(bytes, whole.start) {
            has_unresolved_use = true;
            continue;
        }
        if !resolved_starts.contains(&whole.start) {
            continue;
        }
        let mut open_paren: usize = whole.end;
        while bytes
            .get(open_paren)
            .is_some_and(|byte: &u8| byte.is_ascii_whitespace())
        {
            open_paren += 1;
        }
        if bytes.get(open_paren) != Some(&b'(') {
            has_unresolved_use = true;
            continue;
        }
        let Some(close_paren): Option<usize> = find_paren_close(bytes, open_paren + 1) else {
            has_unresolved_use = true;
            continue;
        };
        if let Some(idx) = parse_int(source[open_paren + 1..close_paren].trim()) {
            out.push(CallSite {
                range: whole.start..close_paren + 1,
                index: idx,
            });
        } else {
            has_unresolved_use = true;
        }
    }
    Ok(CallInventory {
        call_sites: out,
        has_unresolved_use,
    })
}

const fn identifier_is_bounded(bytes: &[u8], start: usize, end: usize) -> bool {
    (start == 0 || !is_ident_byte(bytes[start - 1]))
        && (end >= bytes.len() || !is_ident_byte(bytes[end]))
}

fn is_property_access(bytes: &[u8], start: usize) -> bool {
    let mut cursor: usize = start;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    cursor > 0 && bytes[cursor - 1] == b'.'
}

const fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
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
        let src: &str = "var _arr=['zero','one','two'];var _dec=function(i){return _arr[i];};_dec(0x0);_dec(0x1);_dec(2);";
        let (_, _, decoder_range): (String, String, Range<usize>) =
            find_decoder(src, "_arr").expect("decoder");
        let inventory: CallInventory =
            find_call_sites(src, "_dec", &decoder_range).expect("inventory");
        assert_eq!(inventory.call_sites.len(), 3);
        assert_eq!(inventory.call_sites[0].index, 0);
        assert_eq!(inventory.call_sites[1].index, 1);
        assert_eq!(inventory.call_sites[2].index, 2);
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

    #[test]
    fn inline_consumer_retains_environment_refusal() {
        let src: &str = r"var _0xab = ['hi'];
var _0xdec = function (i) { return _0xab[i] + Math.random(); };
console.log(_0xdec(0x0));
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(
            result.probe_refusal,
            Some(ProbeRefusal::EnvironmentDisagreement)
        );
        assert_eq!(result.call_sites_inlined, 0);
        assert!(result.rewritten_source.contains("_0xdec(0x0)"));
        assert!(result.rewritten_source.contains("var _0xdec"));
    }

    #[test]
    fn partial_inline_keeps_decoder_for_unresolved_calls() {
        let src: &str = r"var _0xab = ['zero', 'one', 'two'];
var _0xdec = function (i) { return i === 1 ? null.missing : _0xab[i]; };
console.log(_0xdec(0x0), _0xdec(0x1), _0xdec(0x2));
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.call_sites_inlined, 2);
        assert!(result.rewritten_source.contains("var _0xdec"));
        assert!(result.rewritten_source.contains("_0xdec(0x1)"));
        assert!(result.rewritten_source.contains("'zero'"));
        assert!(result.rewritten_source.contains("'two'"));
    }

    #[test]
    fn dynamic_only_call_keeps_decoder_declaration() {
        let src: &str = r"var _0xab = ['zero', 'one'];
var _0xdec = function (i) { return _0xab[i]; };
console.log(_0xdec(index));
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.call_sites_inlined, 0);
        assert!(result.rewritten_source.contains("var _0xdec"));
        assert!(result.rewritten_source.contains("_0xdec(index)"));
    }

    #[test]
    fn mixed_literal_and_dynamic_calls_keep_decoder_declaration() {
        let src: &str = r"var _0xab = ['zero', 'one'];
var _0xdec = function (i) { return _0xab[i]; };
console.log(_0xdec(0), _0xdec(index));
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.call_sites_inlined, 1);
        assert!(result.rewritten_source.contains("'zero'"));
        assert!(result.rewritten_source.contains("var _0xdec"));
        assert!(result.rewritten_source.contains("_0xdec(index)"));
    }

    #[test]
    fn escaped_decoder_reference_keeps_decoder_declaration() {
        let src: &str = r"var _0xab = ['zero', 'one'];
var _0xdec = function (i) { return _0xab[i]; };
console.log(_0xdec(0), _0x\u0064ec(1));
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.call_sites_inlined, 1);
        assert!(result.rewritten_source.contains("'zero'"));
        assert!(result.rewritten_source.contains("var _0xdec"));
        assert!(result.rewritten_source.contains(r"_0x\u0064ec(1)"));
    }

    #[test]
    fn template_expression_is_live_but_template_text_is_not() {
        let src: &str = r"var _0xab = ['zero'];
var _0xdec = function (i) { return _0xab[i]; };
console.log('_0xdec(index)', `${_0xdec(index)}`);
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.call_sites_inlined, 0);
        assert!(result.rewritten_source.contains("var _0xdec"));
        assert!(result.rewritten_source.contains("${_0xdec(index)}"));
    }

    #[test]
    fn shadowed_decoder_call_is_not_inlined_as_the_outer_binding() {
        let src: &str = r"var _0xab = ['zero', 'one'];
var _0xdec = function (i) { return _0xab[i]; };
function invoke(_0xdec) { return _0xdec(0); }
console.log(_0xdec(1), invoke(function (value) { return value; }));
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.call_sites_inlined, 1);
        assert!(result.rewritten_source.contains("return _0xdec(0)"));
        assert!(result.rewritten_source.contains("'one'"));
    }

    #[test]
    fn semantic_failure_does_not_inline_ambiguous_legacy_references() {
        let src: &str = "var _0xab=['zero'];var _0xdec=function(i){return _0xab[i];};function invoke(_0xdec){return _0xdec(0);}const =;";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.call_sites_inlined, 0);
        assert!(result.rewritten_source.contains("return _0xdec(0)"));
        assert!(result.rewritten_source.contains("var _0xdec=function"));
    }

    #[test]
    fn global_object_decoder_use_keeps_the_outer_binding() {
        let src: &str = r"var _0xab = ['zero'];
var _0xdec = function (i) { return _0xab[i]; };
console.log(_0xdec(0), globalThis._0xdec(index));
";
        let result: InlineResult = inline_decoder_calls(src, "_0xab");
        assert_eq!(result.call_sites_inlined, 1);
        assert!(result.rewritten_source.contains("var _0xdec"));
        assert!(result.rewritten_source.contains("globalThis._0xdec(index)"));
    }
}
