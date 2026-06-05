use std::ops::Range;

use regex::Regex;

use super::sandbox::{RotationSearchOutcome, probe_expressions, probe_with_rotation_search};
use crate::scan_utils::{find_brace_close, find_paren_close};

#[derive(Debug, Clone)]
pub(super) struct ModernRecovery {
    pub(super) provider_name: String,
    pub(super) decoder_name: String,
    pub(super) call_sites_total: usize,
    pub(super) call_sites_inlined: usize,
    pub(super) rotation_count: u32,
    pub(super) rewritten_source: String,
}

const MAX_CALL_SITES: usize = 65_536;

pub(super) fn recover_modern(source: &str) -> Option<ModernRecovery> {
    let provider: ProviderFn = find_provider(source)?;
    let decoder: DecoderFn = find_decoder(source, &provider.name)?;
    let toplevel_aliases: Vec<AliasDecl> = find_aliases(source, &decoder.name);
    let iife: Option<Range<usize>> = find_rotation_iife(source, &provider.name);

    let accessor_names: Vec<String> = accessor_name_set(source, &decoder.name, &toplevel_aliases);
    let proxies: Vec<ProxyFn> = find_proxy_functions(source, &accessor_names);

    let mut callable_names: Vec<String> = accessor_names.clone();
    for proxy in &proxies {
        if !callable_names.iter().any(|n| n == &proxy.name) {
            callable_names.push(proxy.name.clone());
        }
    }

    let call_sites: Vec<CallSite> = find_call_sites(source, &callable_names, &proxies);
    if call_sites.is_empty() || call_sites.len() > MAX_CALL_SITES {
        return None;
    }

    let prelude_with_iife: String = build_prelude(
        source,
        &provider,
        &decoder,
        &toplevel_aliases,
        &accessor_names,
        &proxies,
        iife.as_ref(),
    );

    let expressions: Vec<String> = call_sites
        .iter()
        .map(|c| source[c.range.clone()].to_owned())
        .collect();
    let initial: Vec<Option<String>> = probe_expressions(&prelude_with_iife, &expressions);
    let (decoded, rotation_count): (Vec<Option<String>>, u32) = if initial
        .iter()
        .any(Option::is_some)
    {
        (initial, 0)
    } else {
        let prelude_no_iife: String = build_prelude(
            source,
            &provider,
            &decoder,
            &toplevel_aliases,
            &accessor_names,
            &proxies,
            None,
        );
        let array_len: usize = provider_array_len(source, &provider).unwrap_or(0);
        let rotation: RotationSearchOutcome =
            probe_with_rotation_search(&prelude_no_iife, &provider.name, &expressions, array_len)?;
        (rotation.decoded, rotation.rotation)
    };
    if decoded.iter().all(Option::is_none) {
        return None;
    }

    let (rewritten, inlined): (String, usize) = inline_sites(
        source,
        &call_sites,
        &decoded,
        &provider,
        iife.as_ref(),
        &decoder,
        &toplevel_aliases,
        &proxies,
    );

    Some(ModernRecovery {
        provider_name: provider.name,
        decoder_name: decoder.name,
        call_sites_total: call_sites.len(),
        call_sites_inlined: inlined,
        rotation_count,
        rewritten_source: rewritten,
    })
}

fn provider_array_len(source: &str, provider: &ProviderFn) -> Option<usize> {
    let body: &str = &source[provider.range.clone()];
    let bytes: &[u8] = body.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let close: usize = find_array_close(bytes, i + 1)?;
            return Some(count_array_items(&body[i + 1..close]));
        }
        i += 1;
    }
    None
}

fn find_array_close(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i: usize = from;
    let mut depth: i32 = 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\'' || b == b'"' || b == b'`' {
            i = crate::scan_utils::skip_string(bytes, i, b)?;
            continue;
        }
        if b == b'[' {
            depth += 1;
        } else if b == b']' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn count_array_items(body: &str) -> usize {
    let bytes: &[u8] = body.as_bytes();
    let mut count: usize = 0;
    let mut saw_item: bool = false;
    let mut i: usize = 0;
    let mut depth: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                if let Some(next) = crate::scan_utils::skip_string(bytes, i, b) {
                    saw_item = true;
                    i = next;
                    continue;
                }
                return count;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                saw_item = true;
            }
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                if saw_item {
                    count += 1;
                    saw_item = false;
                }
            }
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => saw_item = true,
        }
        i += 1;
    }
    if saw_item {
        count += 1;
    }
    count
}

fn accessor_name_set(source: &str, decoder: &str, toplevel_aliases: &[AliasDecl]) -> Vec<String> {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[;,\n)]")
    else {
        return vec![decoder.to_owned()];
    };
    let mut known: Vec<String> = vec![decoder.to_owned()];
    known.extend(toplevel_aliases.iter().map(|a| a.name.clone()));
    let mut progressed: bool = true;
    while progressed {
        progressed = false;
        for cap in re.captures_iter(source) {
            let (Some(lhs), Some(rhs)): (Option<regex::Match<'_>>, Option<regex::Match<'_>>) =
                (cap.get(1), cap.get(2))
            else {
                continue;
            };
            let lhs_name: &str = lhs.as_str();
            let rhs_name: &str = rhs.as_str();
            if known.iter().any(|k| k == rhs_name) && !known.iter().any(|k| k == lhs_name) {
                known.push(lhs_name.to_owned());
                progressed = true;
            }
        }
    }
    known
}

#[derive(Debug, Clone)]
struct ProviderFn {
    name: String,
    range: Range<usize>,
}

#[derive(Debug, Clone)]
struct DecoderFn {
    name: String,
    range: Range<usize>,
}

#[derive(Debug, Clone)]
struct AliasDecl {
    name: String,
    range: Range<usize>,
}

#[derive(Debug, Clone)]
struct ProxyFn {
    name: String,
    range: Range<usize>,
}

#[derive(Debug, Clone)]
struct CallSite {
    range: Range<usize>,
}

fn function_header_re() -> Option<Regex> {
    Regex::new(r"function\s+([A-Za-z_$][\w$]*)\s*\(").ok()
}

fn find_provider(source: &str) -> Option<ProviderFn> {
    let re: Regex = function_header_re()?;
    let bytes: &[u8] = source.as_bytes();
    for cap in re.captures_iter(source) {
        let name: &str = cap.get(1)?.as_str();
        let whole: regex::Match<'_> = cap.get(0)?;
        let open_paren: usize = whole.end() - 1;
        let close_paren: usize = find_paren_close(bytes, open_paren + 1)?;
        let open_brace: usize = next_byte(bytes, close_paren + 1, b'{')?;
        let close_brace: usize = find_brace_close(bytes, open_brace + 1)?;
        let body: &str = &source[open_brace + 1..close_brace];
        if is_provider_body(body, name) {
            return Some(ProviderFn {
                name: name.to_owned(),
                range: whole.start()..close_brace + 1,
            });
        }
    }
    None
}

fn is_provider_body(body: &str, name: &str) -> bool {
    let has_array: bool =
        body.contains('[') && body.contains(']') && (body.contains('\'') || body.contains('"'));
    let self_reassign: bool =
        body.contains(&format!("{name}=")) || body.contains(&format!("{name} ="));
    let returns_self_call: bool =
        body.contains(&format!("return {name}(")) || body.contains(&format!("return {name} ("));
    has_array && self_reassign && returns_self_call
}

fn find_decoder(source: &str, provider: &str) -> Option<DecoderFn> {
    let re: Regex = function_header_re()?;
    let bytes: &[u8] = source.as_bytes();
    for cap in re.captures_iter(source) {
        let name: &str = cap.get(1)?.as_str();
        if name == provider {
            continue;
        }
        let whole: regex::Match<'_> = cap.get(0)?;
        let open_paren: usize = whole.end() - 1;
        let Some(close_paren): Option<usize> = find_paren_close(bytes, open_paren + 1) else {
            continue;
        };
        let Some(open_brace): Option<usize> = next_byte(bytes, close_paren + 1, b'{') else {
            continue;
        };
        let Some(close_brace): Option<usize> = find_brace_close(bytes, open_brace + 1) else {
            continue;
        };
        let body: &str = &source[open_brace + 1..close_brace];
        if is_decoder_body(body, provider) {
            return Some(DecoderFn {
                name: name.to_owned(),
                range: whole.start()..close_brace + 1,
            });
        }
    }
    None
}

fn is_decoder_body(body: &str, provider: &str) -> bool {
    body.contains(&format!("{provider}(")) || body.contains(&format!("{provider} ("))
}

fn find_aliases(source: &str, decoder: &str) -> Vec<AliasDecl> {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[;,\n]")
    else {
        return Vec::new();
    };
    let depths: Vec<usize> = brace_depth_table(source);
    let mut known: Vec<String> = vec![decoder.to_owned()];
    let mut out: Vec<AliasDecl> = Vec::new();
    let mut progressed: bool = true;
    while progressed {
        progressed = false;
        for cap in re.captures_iter(source) {
            let Some(lhs): Option<regex::Match<'_>> = cap.get(1) else {
                continue;
            };
            let Some(rhs): Option<regex::Match<'_>> = cap.get(2) else {
                continue;
            };
            let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
                continue;
            };
            if depths.get(whole.start()).copied().unwrap_or(1) != 0 {
                continue;
            }
            let lhs_name: String = lhs.as_str().to_owned();
            let rhs_name: &str = rhs.as_str();
            if known.iter().any(|k| k == rhs_name)
                && lhs_name != decoder
                && !out.iter().any(|a| a.name == lhs_name)
            {
                known.push(lhs_name.clone());
                out.push(AliasDecl {
                    name: lhs_name,
                    range: whole.start()..trim_decl_end(source, whole.start(), whole.end()),
                });
                progressed = true;
            }
        }
    }
    out
}

fn trim_decl_end(source: &str, start: usize, end: usize) -> usize {
    let bytes: &[u8] = source.as_bytes();
    if end > start && matches!(bytes.get(end - 1), Some(b';' | b',' | b'\n')) {
        end - 1
    } else {
        end
    }
}

fn trim_decl_end_inclusive(source: &str, decl_end: usize) -> usize {
    let bytes: &[u8] = source.as_bytes();
    if matches!(bytes.get(decl_end), Some(b';')) {
        decl_end + 1
    } else {
        decl_end
    }
}

fn brace_depth_table(source: &str) -> Vec<usize> {
    let bytes: &[u8] = source.as_bytes();
    let mut table: Vec<usize> = Vec::with_capacity(bytes.len());
    let mut depth: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\'' || b == b'"' || b == b'`' {
            let next: usize = crate::scan_utils::skip_string(bytes, i, b).unwrap_or(bytes.len());
            while i < next && i < bytes.len() {
                table.push(depth);
                i += 1;
            }
            continue;
        }
        table.push(depth);
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth = depth.saturating_sub(1);
        }
        i += 1;
    }
    table
}

fn find_rotation_iife(source: &str, provider: &str) -> Option<Range<usize>> {
    let re: Regex = Regex::new(r"\(function\s*\([^)]*\)\s*\{").ok()?;
    let bytes: &[u8] = source.as_bytes();
    for m in re.find_iter(source) {
        let outer_open: usize = m.start();
        let open_brace: usize = m.end() - 1;
        let Some(close_brace): Option<usize> = find_brace_close(bytes, open_brace + 1) else {
            continue;
        };
        let body: &str = &source[open_brace + 1..close_brace];
        let looks_rotational: bool =
            body.contains("push") && body.contains("shift") && body.contains("parseInt");
        if !looks_rotational {
            continue;
        }
        let Some(outer_close): Option<usize> = find_paren_close(bytes, outer_open + 1) else {
            continue;
        };
        if !source[open_brace + 1..outer_close].contains(provider)
            && !source[close_brace..outer_close].contains(provider)
        {
            continue;
        }
        let end: usize = swallow_semicolon(bytes, outer_close + 1);
        return Some(outer_open..end);
    }
    None
}

fn swallow_semicolon(bytes: &[u8], from: usize) -> usize {
    let mut i: usize = from;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    if matches!(bytes.get(i), Some(b';')) {
        i + 1
    } else {
        from
    }
}

#[allow(clippy::too_many_arguments)]
fn build_prelude(
    source: &str,
    provider: &ProviderFn,
    decoder: &DecoderFn,
    toplevel_aliases: &[AliasDecl],
    accessor_names: &[String],
    proxies: &[ProxyFn],
    iife: Option<&Range<usize>>,
) -> String {
    let proxy_len: usize = proxies.iter().map(|p| p.range.len()).sum();
    let mut prelude: String = String::with_capacity(
        provider.range.len() + decoder.range.len() + proxy_len + iife.map_or(0, Range::len) + 256,
    );
    prelude.push_str(&source[provider.range.clone()]);
    prelude.push('\n');
    prelude.push_str(&source[decoder.range.clone()]);
    prelude.push('\n');
    for alias in toplevel_aliases {
        prelude.push_str(&source[alias.range.clone()]);
        prelude.push_str(";\n");
    }
    for name in accessor_names {
        if name == &decoder.name || toplevel_aliases.iter().any(|a| &a.name == name) {
            continue;
        }
        prelude.push_str("var ");
        prelude.push_str(name);
        prelude.push('=');
        prelude.push_str(&decoder.name);
        prelude.push_str(";\n");
    }
    for proxy in proxies {
        prelude.push_str(&source[proxy.range.clone()]);
        prelude.push('\n');
    }
    if let Some(iife_range) = iife {
        prelude.push_str(&source[iife_range.clone()]);
        prelude.push('\n');
    }
    prelude
}

fn find_proxy_functions(source: &str, accessor_names: &[String]) -> Vec<ProxyFn> {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{\s*return\s+([A-Za-z_$][\w$]*)\s*\(",
    ) else {
        return Vec::new();
    };
    let bytes: &[u8] = source.as_bytes();
    let mut known: Vec<String> = accessor_names.to_vec();
    let mut out: Vec<ProxyFn> = Vec::new();
    let mut progressed: bool = true;
    while progressed {
        progressed = false;
        for cap in re.captures_iter(source) {
            let (Some(name_m), Some(callee_m)): (
                Option<regex::Match<'_>>,
                Option<regex::Match<'_>>,
            ) = (cap.get(1), cap.get(3)) else {
                continue;
            };
            let name: &str = name_m.as_str();
            let callee: &str = callee_m.as_str();
            if !known.iter().any(|k| k == callee) || known.iter().any(|k| k == name) {
                continue;
            }
            let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
                continue;
            };
            let Some(rel): Option<usize> = source[whole.start()..whole.end()].rfind('{') else {
                continue;
            };
            let header_open_brace: usize = whole.start() + rel;
            let Some(close_brace): Option<usize> = find_brace_close(bytes, header_open_brace + 1)
            else {
                continue;
            };
            known.push(name.to_owned());
            out.push(ProxyFn {
                name: name.to_owned(),
                range: whole.start()..close_brace + 1,
            });
            progressed = true;
        }
    }
    out
}

fn find_call_sites(source: &str, callable_names: &[String], proxies: &[ProxyFn]) -> Vec<CallSite> {
    let alternation: String = callable_names
        .iter()
        .map(|n| regex::escape(n))
        .collect::<Vec<String>>()
        .join("|");
    if alternation.is_empty() {
        return Vec::new();
    }
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&format!(r"\b(?:{alternation})\s*\("))
    else {
        return Vec::new();
    };
    let bytes: &[u8] = source.as_bytes();
    let proxy_ranges: Vec<&Range<usize>> = proxies.iter().map(|p| &p.range).collect();
    let mut out: Vec<CallSite> = Vec::new();
    for m in re.find_iter(source) {
        let open_paren: usize = m.end() - 1;
        if proxy_ranges
            .iter()
            .any(|r| m.start() >= r.start && m.start() < r.end)
        {
            continue;
        }
        let Some(close_paren): Option<usize> = find_paren_close(bytes, open_paren + 1) else {
            continue;
        };
        let args: &str = &source[open_paren + 1..close_paren];
        if !args_are_inlineable(args) {
            continue;
        }
        out.push(CallSite {
            range: m.start()..close_paren + 1,
        });
    }
    out
}

fn args_are_inlineable(args: &str) -> bool {
    let trimmed: &str = args.trim();
    if trimmed.is_empty() {
        return false;
    }
    for part in split_top_level_args(trimmed) {
        let p: &str = part.trim();
        let is_number: bool = parse_int(p).is_some();
        let is_string: bool = (p.starts_with('\'') && p.ends_with('\'') && p.len() >= 2)
            || (p.starts_with('"') && p.ends_with('"') && p.len() >= 2);
        if !is_number && !is_string {
            return false;
        }
    }
    true
}

fn split_top_level_args(args: &str) -> Vec<&str> {
    let bytes: &[u8] = args.as_bytes();
    let mut parts: Vec<&str> = Vec::new();
    let mut start: usize = 0;
    let mut depth: i32 = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                if let Some(next) = crate::scan_utils::skip_string(bytes, i, b) {
                    i = next;
                    continue;
                }
                return vec![args];
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&args[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&args[start..]);
    parts
}

#[allow(clippy::too_many_arguments)]
fn inline_sites(
    source: &str,
    call_sites: &[CallSite],
    decoded: &[Option<String>],
    provider: &ProviderFn,
    iife: Option<&Range<usize>>,
    decoder: &DecoderFn,
    aliases: &[AliasDecl],
    proxies: &[ProxyFn],
) -> (String, usize) {
    enum Event {
        Remove(Range<usize>),
        Call(Range<usize>, Option<String>),
    }
    let mut events: Vec<Event> =
        Vec::with_capacity(call_sites.len() + aliases.len() + proxies.len() + 3);
    events.push(Event::Remove(provider.range.clone()));
    events.push(Event::Remove(decoder.range.clone()));
    if let Some(iife_range) = iife {
        events.push(Event::Remove(iife_range.clone()));
    }
    for alias in aliases {
        events.push(Event::Remove(
            alias.range.start..trim_decl_end_inclusive(source, alias.range.end),
        ));
    }
    for proxy in proxies {
        events.push(Event::Remove(proxy.range.clone()));
    }
    for (site, value) in call_sites.iter().zip(decoded.iter()) {
        events.push(Event::Call(site.range.clone(), value.clone()));
    }
    events.sort_by_key(|e| match e {
        Event::Remove(r) | Event::Call(r, _) => r.start,
    });

    let mut rewritten: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut inlined: usize = 0;
    for event in events {
        let (start, end): (usize, usize) = match &event {
            Event::Remove(r) | Event::Call(r, _) => (r.start, r.end),
        };
        if start < cursor {
            continue;
        }
        rewritten.push_str(&source[cursor..start]);
        match event {
            Event::Remove(_) => {}
            Event::Call(_, value) => {
                if let Some(text) = value {
                    rewritten.push_str(&js_quote(&text));
                    inlined += 1;
                } else {
                    rewritten.push_str(&source[start..end]);
                }
            }
        }
        cursor = end;
    }
    rewritten.push_str(&source[cursor..]);
    (rewritten, inlined)
}

fn next_byte(bytes: &[u8], from: usize, target: u8) -> Option<usize> {
    let mut i: usize = from;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == target {
            return Some(i);
        }
        if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            return None;
        }
        i += 1;
    }
    None
}

fn parse_int(s: &str) -> Option<i64> {
    let trimmed: &str = s.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = trimmed.strip_prefix("-0x") {
        return i64::from_str_radix(hex, 16).ok().map(|v| -v);
    }
    trimmed.parse::<i64>().ok()
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
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const MODERN_SAMPLE: &str = "function p(){const a=['log','hello','world'];p=function(){return a;};return p();}const g=d;function d(i,_){i=i-0x0;const a=p();return a[i];}console[g(0x0)](d(0x1),d(0x2));";

    #[test]
    fn finds_provider_and_decoder() {
        let provider: ProviderFn = find_provider(MODERN_SAMPLE).expect("provider");
        assert_eq!(provider.name, "p");
        let decoder: DecoderFn = find_decoder(MODERN_SAMPLE, "p").expect("decoder");
        assert_eq!(decoder.name, "d");
    }

    #[test]
    fn finds_alias() {
        let aliases: Vec<AliasDecl> = find_aliases(MODERN_SAMPLE, "d");
        let names: Vec<String> = aliases.into_iter().map(|a| a.name).collect();
        assert_eq!(names, vec!["g".to_owned()]);
    }

    #[test]
    fn end_to_end_modern_recovery() {
        let rec: ModernRecovery = recover_modern(MODERN_SAMPLE).expect("recovery");
        assert_eq!(rec.provider_name, "p");
        assert_eq!(rec.decoder_name, "d");
        assert!(
            rec.call_sites_inlined >= 2,
            "expected >=2 inlined, got {}",
            rec.call_sites_inlined
        );
        assert!(
            rec.rewritten_source.contains("'hello'"),
            "got: {}",
            rec.rewritten_source
        );
        assert!(rec.rewritten_source.contains("'world'"));
        assert!(rec.rewritten_source.contains("'log'"));
        assert!(
            !rec.rewritten_source.contains("function d("),
            "decoder must be stripped"
        );
    }

    #[test]
    fn parse_int_handles_hex_and_negative() {
        assert_eq!(parse_int("0x1f"), Some(31));
        assert_eq!(parse_int("-0x2"), Some(-2));
        assert_eq!(parse_int("42"), Some(42));
    }

    const PROXY_SAMPLE: &str = "function p(){const a=['log','hello','world'];p=function(){return a;};return p();}function d(i,_){i=i-0x0;const a=p();return a[i];}function w(_x,_y){return d(_x- -0x0,_y);}console[w(0x0,0x9)](w(0x1,0x9),w(0x2,0x9));";

    #[test]
    fn detects_wrapper_proxy_functions() {
        let proxies: Vec<ProxyFn> = find_proxy_functions(PROXY_SAMPLE, &["d".to_owned()]);
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name, "w");
    }

    #[test]
    fn end_to_end_proxy_recovery() {
        let rec: ModernRecovery = recover_modern(PROXY_SAMPLE).expect("proxy recovery");
        assert!(
            rec.call_sites_inlined >= 2,
            "proxy call sites must inline, got {}",
            rec.call_sites_inlined
        );
        assert!(
            rec.rewritten_source.contains("'hello'"),
            "got: {}",
            rec.rewritten_source
        );
        assert!(
            rec.rewritten_source.contains("'world'"),
            "got: {}",
            rec.rewritten_source
        );
        assert!(
            !rec.rewritten_source.contains("function w("),
            "proxy must be stripped"
        );
    }

    #[test]
    fn args_inlineable_accepts_literals_only() {
        assert!(args_are_inlineable("0x1, 'a', 42"));
        assert!(!args_are_inlineable("0x1, foo, 42"));
        assert!(!args_are_inlineable(""));
    }

    #[test]
    fn split_top_level_args_respects_nesting() {
        let parts: Vec<&str> = split_top_level_args("0x1, f(0x2, 0x3), 'a,b'");
        assert_eq!(parts.len(), 3);
    }
}
