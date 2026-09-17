use std::collections::BTreeSet;
use std::ops::Range;

use regex::Regex;

use super::sandbox::{
    MAX_PROBE_EXPRESSIONS, MAX_SCRIPT_BYTES, ProbeRefusal, RotationSearchOutcome,
    probe_expressions, probe_rotation_to_match, probe_with_rotation_search,
    validate_batched_expression_lengths,
};
use super::{executable_code_exclusions, resolved_reference_starts};
use crate::scan_utils::{
    find_brace_close, find_paren_close, find_statement_end, regex_can_follow, skip_regex_literal,
    skip_string,
};

#[derive(Debug, Clone)]
pub(super) struct ModernRecovery {
    pub(super) provider_name: String,
    pub(super) decoder_name: String,
    pub(super) call_sites_total: usize,
    pub(super) call_sites_inlined: usize,
    pub(super) rotation_count: u32,
    pub(super) scaffolding_removed: bool,
    pub(super) rewritten_source: String,
}

pub(super) fn recover_modern(source: &str) -> Result<Option<ModernRecovery>, ProbeRefusal> {
    let Some(provider): Option<ProviderFn> = find_provider(source) else {
        return Ok(None);
    };
    let Some(decoder): Option<DecoderFn> = find_decoder(source, &provider.name) else {
        return Ok(None);
    };
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

    let alias_removals: Vec<Range<usize>> = find_inbody_alias_edits(source, &accessor_names);
    let removal_ranges: Vec<Range<usize>> = candidate_removal_ranges(
        source,
        &provider,
        &decoder,
        iife.as_ref(),
        &toplevel_aliases,
        &proxies,
        &alias_removals,
    );
    let inventory: CallInventory =
        find_call_sites(source, &callable_names, &provider.name, &removal_ranges)?;
    let call_sites: Vec<CallSite> = inventory.call_sites;
    if call_sites.is_empty() {
        return if inventory.has_unresolved_use {
            Ok(Some(ModernRecovery {
                provider_name: provider.name,
                decoder_name: decoder.name,
                call_sites_total: 0,
                call_sites_inlined: 0,
                rotation_count: 0,
                scaffolding_removed: false,
                rewritten_source: source.to_owned(),
            }))
        } else {
            Ok(None)
        };
    }

    let prelude_with_iife: String = build_prelude(
        source,
        &provider,
        &decoder,
        &toplevel_aliases,
        &accessor_names,
        &proxies,
        iife.as_ref(),
    )?;

    validate_batched_expression_lengths(
        call_sites.iter().map(|site: &CallSite| site.range.len()),
        call_sites.len(),
    )?;
    let mut expressions: Vec<String> = Vec::new();
    expressions
        .try_reserve_exact(call_sites.len())
        .map_err(|_| ProbeRefusal::BoundExceeded)?;
    expressions.extend(
        call_sites
            .iter()
            .map(|site: &CallSite| source[site.range.clone()].to_owned()),
    );
    let (decoded, rotation_count): (Vec<Option<String>>, u32) = if iife.is_some() {
        resolve_with_rotation(
            source,
            &provider,
            &decoder,
            &toplevel_aliases,
            &accessor_names,
            &proxies,
            &prelude_with_iife,
            &expressions,
        )?
    } else {
        match probe_expressions(&prelude_with_iife, &expressions) {
            Ok(decoded) => (decoded, 0),
            Err(refusal) => {
                return Err(refusal);
            }
        }
    };
    if decoded.iter().all(Option::is_none) {
        return Err(ProbeRefusal::EvaluationFailed);
    }

    let (rewritten, inlined, scaffolding_removed): (String, usize, bool) = inline_sites(
        source,
        &call_sites,
        &decoded,
        inventory.has_unresolved_use,
        &provider,
        iife.as_ref(),
        &decoder,
        &toplevel_aliases,
        &proxies,
        &alias_removals,
    );

    Ok(Some(ModernRecovery {
        provider_name: provider.name,
        decoder_name: decoder.name,
        call_sites_total: call_sites.len(),
        call_sites_inlined: inlined,
        rotation_count,
        scaffolding_removed,
        rewritten_source: rewritten,
    }))
}

#[allow(clippy::too_many_arguments)]
fn resolve_with_rotation(
    source: &str,
    provider: &ProviderFn,
    decoder: &DecoderFn,
    toplevel_aliases: &[AliasDecl],
    accessor_names: &[String],
    proxies: &[ProxyFn],
    prelude_with_iife: &str,
    expressions: &[String],
) -> Result<(Vec<Option<String>>, u32), ProbeRefusal> {
    let prelude_no_iife: String = build_prelude(
        source,
        provider,
        decoder,
        toplevel_aliases,
        accessor_names,
        proxies,
        None,
    )?;
    let array_len: usize = provider_array_len(source, provider).unwrap_or(0);
    let reference: Vec<Option<String>> = probe_expressions(prelude_with_iife, expressions)?;
    if reference.iter().any(Option::is_some) {
        let count: u32 = probe_rotation_to_match(
            &prelude_no_iife,
            &provider.name,
            expressions,
            &reference,
            array_len,
        )?;
        return Ok((reference, count));
    }
    let search: Result<RotationSearchOutcome, ProbeRefusal> =
        probe_with_rotation_search(&prelude_no_iife, &provider.name, expressions, array_len);
    match search {
        Ok(rotation) => Ok((rotation.decoded, rotation.rotation)),
        Err(refusal) => Err(refusal),
    }
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

#[derive(Debug, Clone)]
struct CallInventory {
    call_sites: Vec<CallSite>,
    has_unresolved_use: bool,
}

#[derive(Debug, Clone, Copy)]
struct IdentifierUse {
    start: usize,
    end: usize,
    is_callable: bool,
    is_provider: bool,
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
) -> Result<String, ProbeRefusal> {
    let mut capacity: usize = 0;
    {
        let mut include = |additional: usize| -> Result<(), ProbeRefusal> {
            capacity = capacity
                .checked_add(additional)
                .ok_or(ProbeRefusal::InputTooLarge)?;
            if capacity > MAX_SCRIPT_BYTES {
                return Err(ProbeRefusal::InputTooLarge);
            }
            Ok(())
        };
        include(provider.range.len())?;
        include(1)?;
        include(decoder.range.len())?;
        include(1)?;
        for alias in toplevel_aliases {
            include(alias.range.len())?;
            include(2)?;
        }
        for name in accessor_names {
            if name == &decoder.name
                || toplevel_aliases
                    .iter()
                    .any(|alias: &AliasDecl| &alias.name == name)
            {
                continue;
            }
            include(4)?;
            include(name.len())?;
            include(1)?;
            include(decoder.name.len())?;
            include(2)?;
        }
        for proxy in proxies {
            include(proxy.range.len())?;
            include(1)?;
        }
        if let Some(iife_range) = iife {
            include(iife_range.len())?;
            include(1)?;
        }
    }
    let mut prelude: String = String::new();
    prelude
        .try_reserve_exact(capacity)
        .map_err(|_| ProbeRefusal::BoundExceeded)?;
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
    Ok(prelude)
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

fn find_call_sites(
    source: &str,
    callable_names: &[String],
    provider_name: &str,
    removal_ranges: &[Range<usize>],
) -> Result<CallInventory, ProbeRefusal> {
    let callable: BTreeSet<&str> = callable_names.iter().map(String::as_str).collect();
    let mut excluded: Vec<Range<usize>> = executable_code_exclusions(source)?;
    excluded.extend(removal_ranges.iter().cloned());
    excluded.sort_by_key(|range: &Range<usize>| range.start);
    let excluded: Vec<Range<usize>> = merge_ranges(excluded);
    let bytes: &[u8] = source.as_bytes();
    let mut identifiers: Vec<IdentifierUse> = Vec::new();
    let mut excluded_index: usize = 0;
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        while excluded_index < excluded.len() && excluded[excluded_index].end <= cursor {
            excluded_index += 1;
        }
        if let Some(range) = excluded.get(excluded_index)
            && range.start <= cursor
        {
            cursor = range.end;
            continue;
        }
        if !is_ident_start(bytes[cursor]) {
            cursor += 1;
            continue;
        }
        let start: usize = cursor;
        cursor += 1;
        while cursor < bytes.len() && is_ident_byte(bytes[cursor]) {
            cursor += 1;
        }
        let name: &str = &source[start..cursor];
        let is_callable: bool = callable.contains(name);
        let is_provider: bool = name == provider_name;
        if !is_callable && !is_provider {
            continue;
        }
        if identifiers.len() == MAX_PROBE_EXPRESSIONS {
            return Err(ProbeRefusal::BoundExceeded);
        }
        identifiers
            .try_reserve(1)
            .map_err(|_| ProbeRefusal::BoundExceeded)?;
        identifiers.push(IdentifierUse {
            start,
            end: cursor,
            is_callable,
            is_provider,
        });
    }
    let mut resolved_names: Vec<&str> = callable_names.iter().map(String::as_str).collect();
    resolved_names.push(provider_name);
    let Some(resolved_starts): Option<BTreeSet<usize>> =
        resolved_reference_starts(source, &resolved_names, removal_ranges)
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
        .map(|identifier: &IdentifierUse| identifier.start)
        .collect();
    let mut has_unresolved_use: bool = resolved_starts.iter().any(|start: &usize| {
        !removal_ranges
            .iter()
            .any(|range: &Range<usize>| range.contains(start))
            && !scanned_starts.contains(start)
    });
    for identifier in identifiers {
        if is_property_access(bytes, identifier.start) {
            has_unresolved_use = true;
            continue;
        }
        if !resolved_starts.contains(&identifier.start) {
            continue;
        }
        let mut open_paren: usize = identifier.end;
        while bytes
            .get(open_paren)
            .is_some_and(|byte: &u8| byte.is_ascii_whitespace())
        {
            open_paren += 1;
        }
        if !identifier.is_callable || identifier.is_provider || bytes.get(open_paren) != Some(&b'(')
        {
            has_unresolved_use = true;
            continue;
        }
        let Some(close_paren): Option<usize> = find_paren_close(bytes, open_paren + 1) else {
            has_unresolved_use = true;
            continue;
        };
        let args: &str = &source[open_paren + 1..close_paren];
        if !args_are_inlineable(args) {
            has_unresolved_use = true;
            continue;
        }
        out.push(CallSite {
            range: identifier.start..close_paren + 1,
        });
    }
    Ok(CallInventory {
        call_sites: out,
        has_unresolved_use,
    })
}

fn merge_ranges(ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

#[allow(clippy::too_many_arguments)]
fn candidate_removal_ranges(
    source: &str,
    provider: &ProviderFn,
    decoder: &DecoderFn,
    iife: Option<&Range<usize>>,
    aliases: &[AliasDecl],
    proxies: &[ProxyFn],
    alias_removals: &[Range<usize>],
) -> Vec<Range<usize>> {
    let mut ranges: Vec<Range<usize>> = Vec::with_capacity(
        aliases.len() + proxies.len() + alias_removals.len() + usize::from(iife.is_some()) + 2,
    );
    ranges.push(provider.range.clone());
    ranges.push(decoder.range.clone());
    if let Some(iife_range) = iife {
        ranges.push(iife_range.clone());
    }
    ranges.extend(aliases.iter().map(|alias: &AliasDecl| {
        alias.range.start..trim_decl_end_inclusive(source, alias.range.end)
    }));
    ranges.extend(proxies.iter().map(|proxy: &ProxyFn| proxy.range.clone()));
    ranges.extend(alias_removals.iter().cloned());
    ranges
}

const fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

fn is_property_access(bytes: &[u8], start: usize) -> bool {
    let mut cursor: usize = start;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    cursor > 0 && bytes[cursor - 1] == b'.'
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
    has_unresolved_use: bool,
    provider: &ProviderFn,
    iife: Option<&Range<usize>>,
    decoder: &DecoderFn,
    aliases: &[AliasDecl],
    proxies: &[ProxyFn],
    alias_removals: &[Range<usize>],
) -> (String, usize, bool) {
    enum Event {
        Remove(Range<usize>),
        Call(Range<usize>, Option<String>),
    }
    let mut events: Vec<Event> = Vec::with_capacity(
        call_sites.len() + aliases.len() + proxies.len() + alias_removals.len() + 3,
    );
    let every_call_decoded: bool = !has_unresolved_use
        && decoded.len() == call_sites.len()
        && decoded.iter().all(|value: &Option<String>| value.is_some());
    if every_call_decoded {
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
        for removal in alias_removals {
            events.push(Event::Remove(removal.clone()));
        }
    }
    for (site, value) in call_sites.iter().zip(decoded.iter()) {
        events.push(Event::Call(site.range.clone(), value.clone()));
    }
    let event_bounds = |event: &Event| -> (usize, usize) {
        match event {
            Event::Remove(r) | Event::Call(r, _) => (r.start, r.end),
        }
    };
    events.sort_by(|a: &Event, b: &Event| {
        let (a_start, a_end): (usize, usize) = event_bounds(a);
        let (b_start, b_end): (usize, usize) = event_bounds(b);
        a_start.cmp(&b_start).then(b_end.cmp(&a_end))
    });

    let mut rewritten: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut inlined: usize = 0;
    for event in events {
        let (start, end): (usize, usize) = event_bounds(&event);
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
    (rewritten, inlined, every_call_decoded)
}

fn find_inbody_alias_edits(source: &str, accessor_names: &[String]) -> Vec<Range<usize>> {
    let Ok(kw_re): Result<Regex, regex::Error> = Regex::new(r"\b(?:var|let|const)\b") else {
        return Vec::new();
    };
    let Ok(alias_re): Result<Regex, regex::Error> =
        Regex::new(r"^([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)$")
    else {
        return Vec::new();
    };
    let depths: Vec<usize> = brace_depth_table(source);
    let bytes: &[u8] = source.as_bytes();
    let mut removals: Vec<Range<usize>> = Vec::new();
    for m in kw_re.find_iter(source) {
        let kw_start: usize = m.start();
        if depths.get(kw_start).copied().unwrap_or(0) == 0 {
            continue;
        }
        let decl_start: usize = m.end();
        let Some(semi): Option<usize> = find_statement_end(bytes, decl_start) else {
            continue;
        };
        let stmt_end: usize = semi + 1;
        let Some(parts): Option<Vec<Range<usize>>> = split_declarators(source, decl_start, semi)
        else {
            continue;
        };
        let alias_indices: Vec<usize> = parts
            .iter()
            .enumerate()
            .filter_map(|(idx, part): (usize, &Range<usize>)| {
                is_accessor_alias(&source[part.clone()], &alias_re, accessor_names).then_some(idx)
            })
            .collect();
        if alias_indices.is_empty() {
            continue;
        }
        if alias_indices.len() == parts.len() {
            removals.push(kw_start..stmt_end);
            continue;
        }
        if alias_indices.len() > 1 {
            continue;
        }
        let k: usize = alias_indices[0];
        let removed_name: &str = alias_lhs(source[parts[k].clone()].trim());
        let value_used: bool =
            parts
                .iter()
                .enumerate()
                .any(|(idx, part): (usize, &Range<usize>)| {
                    idx != k && used_as_value(&source[part.clone()], removed_name)
                });
        if value_used {
            continue;
        }
        if let Some(next) = parts.get(k + 1) {
            let content_start: usize = declarator_content_start(source, &parts[k]);
            removals.push(content_start..next.start);
        } else {
            removals.push(parts[k].start - 1..parts[k].end);
        }
    }
    removals
}

fn declarator_content_start(source: &str, part: &Range<usize>) -> usize {
    let slice: &str = &source[part.clone()];
    part.start + (slice.len() - slice.trim_start().len())
}

fn is_accessor_alias(declarator: &str, alias_re: &Regex, accessor_names: &[String]) -> bool {
    let text: &str = declarator.trim();
    alias_re.captures(text).is_some_and(|caps| {
        let (Some(lhs), Some(rhs)): (Option<regex::Match<'_>>, Option<regex::Match<'_>>) =
            (caps.get(1), caps.get(2))
        else {
            return false;
        };
        accessor_names.iter().any(|n: &String| n == lhs.as_str())
            && accessor_names.iter().any(|n: &String| n == rhs.as_str())
    })
}

fn alias_lhs(declarator: &str) -> &str {
    declarator
        .split_once('=')
        .map_or(declarator, |(lhs, _)| lhs.trim())
}

fn used_as_value(haystack: &str, word: &str) -> bool {
    let hay: &[u8] = haystack.as_bytes();
    let needle: &[u8] = word.as_bytes();
    if needle.is_empty() {
        return false;
    }
    let mut i: usize = 0;
    while let Some(rel) = haystack[i..].find(word) {
        let at: usize = i + rel;
        let before_ok: bool = at == 0 || !is_ident_byte(hay[at - 1]);
        let after: usize = at + needle.len();
        let after_ok: bool = after >= hay.len() || !is_ident_byte(hay[after]);
        if before_ok && after_ok {
            let mut j: usize = after;
            while j < hay.len() && matches!(hay[j], b' ' | b'\t' | b'\r' | b'\n') {
                j += 1;
            }
            if hay.get(j) != Some(&b'(') {
                return true;
            }
        }
        i = at + 1;
    }
    false
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn split_declarators(source: &str, start: usize, end: usize) -> Option<Vec<Range<usize>>> {
    let bytes: &[u8] = source.as_bytes();
    let mut parts: Vec<Range<usize>> = Vec::new();
    let mut seg_start: usize = start;
    let mut depth: i32 = 0;
    let mut prev_significant: u8 = b'=';
    let mut i: usize = start;
    while i < end {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, b)?;
                prev_significant = b;
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < end && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < end && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(end);
                continue;
            }
            b'/' if regex_can_follow(prev_significant) => {
                i = skip_regex_literal(bytes, i);
                prev_significant = b'/';
                continue;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                prev_significant = b;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                prev_significant = b;
            }
            b',' if depth == 0 => {
                parts.push(seg_start..i);
                seg_start = i + 1;
            }
            _ => {
                if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                    prev_significant = b;
                }
            }
        }
        i += 1;
    }
    parts.push(seg_start..end);
    Some(parts)
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
        let rec: ModernRecovery = recover_modern(MODERN_SAMPLE)
            .expect("probe")
            .expect("recovery");
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
    fn modern_consumer_refuses_environment_dependent_values() {
        let source: &str = "function p(){const a=['log'];p=function(){return a;};return p();}function d(i,_){const a=p();return a[i]+Math.random();}console.log(d(0x0));";
        assert_eq!(
            recover_modern(source).expect_err("unstable value"),
            ProbeRefusal::EnvironmentDisagreement
        );
    }

    #[test]
    fn partial_modern_recovery_keeps_required_scaffolding() {
        let source: &str = "function p(){const a=['zero','one','two'];p=function(){return a;};return p();}function d(i,_){const a=p();if(i===1){throw new Error('missing');}return a[i];}console.log(d(0x0),d(0x1),d(0x2));";
        let recovery: ModernRecovery = recover_modern(source).expect("shape").expect("recovery");
        assert_eq!(recovery.call_sites_inlined, 2);
        assert!(recovery.rewritten_source.contains("function p("));
        assert!(recovery.rewritten_source.contains("function d("));
        assert!(recovery.rewritten_source.contains("d(0x1)"));
        assert!(recovery.rewritten_source.contains("'zero'"));
        assert!(recovery.rewritten_source.contains("'two'"));
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
        let rec: ModernRecovery = recover_modern(PROXY_SAMPLE)
            .expect("probe")
            .expect("proxy recovery");
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

    #[test]
    fn dynamic_only_modern_call_keeps_all_required_scaffolding() {
        let source: &str = "function p(){const a=['zero','one'];p=function(){return a;};return p();}function d(i,_){const a=p();return a[i];}console.log(d(index));";
        let recovery: ModernRecovery = recover_modern(source).expect("shape").expect("recovery");
        assert_eq!(recovery.call_sites_inlined, 0);
        assert!(recovery.rewritten_source.contains("function p("));
        assert!(recovery.rewritten_source.contains("function d("));
        assert!(recovery.rewritten_source.contains("d(index)"));
    }

    #[test]
    fn mixed_modern_calls_inline_literals_without_removing_scaffolding() {
        let source: &str = "function p(){const a=['zero','one'];p=function(){return a;};return p();}const a=d;function d(i,_){const v=p();return v[i];}function w(i){return a(i);}console.log(d(0),w(index));";
        let recovery: ModernRecovery = recover_modern(source).expect("shape").expect("recovery");
        assert_eq!(recovery.call_sites_inlined, 1);
        assert!(recovery.rewritten_source.contains("'zero'"));
        assert!(recovery.rewritten_source.contains("function p("));
        assert!(recovery.rewritten_source.contains("function d("));
        assert!(recovery.rewritten_source.contains("const a=d"));
        assert!(recovery.rewritten_source.contains("function w("));
        assert!(recovery.rewritten_source.contains("w(index)"));
    }

    #[test]
    fn escaped_modern_decoder_reference_keeps_scaffolding() {
        let source: &str = r"function p(){const a=['zero','one'];p=function(){return a;};return p();}function d(i,_){const v=p();return v[i];}console.log(d(0),\u0064(1));";
        let recovery: ModernRecovery = recover_modern(source).expect("shape").expect("recovery");
        assert_eq!(recovery.call_sites_inlined, 1);
        assert!(recovery.rewritten_source.contains("'zero'"));
        assert!(recovery.rewritten_source.contains("function p("));
        assert!(recovery.rewritten_source.contains("function d("));
        assert!(recovery.rewritten_source.contains(r"\u0064(1)"));
    }

    #[test]
    fn modern_template_expression_keeps_scaffolding_while_text_is_ignored() {
        let source: &str = "function p(){const a=['zero'];p=function(){return a;};return p();}function d(i,_){const v=p();return v[i];}console.log('d(index)',`${d(index)}`);";
        let recovery: ModernRecovery = recover_modern(source).expect("shape").expect("recovery");
        assert_eq!(recovery.call_sites_inlined, 0);
        assert!(recovery.rewritten_source.contains("function p("));
        assert!(recovery.rewritten_source.contains("function d("));
        assert!(recovery.rewritten_source.contains("${d(index)}"));
    }

    #[test]
    fn shadowed_modern_decoder_call_is_not_inlined_as_the_outer_binding() {
        let source: &str = "function p(){const a=['zero','one'];p=function(){return a;};return p();}function d(i,_){const v=p();return v[i];}function invoke(d){const value=d(0);return value;}console.log(d(1),invoke(function(value){return value;}));";
        let recovery: ModernRecovery = recover_modern(source).expect("shape").expect("recovery");
        assert_eq!(recovery.call_sites_inlined, 1);
        assert!(recovery.rewritten_source.contains("const value=d(0)"));
        assert!(recovery.rewritten_source.contains("'one'"));
    }

    #[test]
    fn semantic_failure_does_not_inline_ambiguous_modern_references() {
        let source: &str = "function p(){const a=['zero'];p=function(){return a;};return p();}function d(i,_){const v=p();return v[i];}function invoke(d){const value=d(0);return value;}const =;";
        let recovery: ModernRecovery = recover_modern(source).expect("shape").expect("recovery");
        assert_eq!(recovery.call_sites_inlined, 0);
        assert!(recovery.rewritten_source.contains("const value=d(0)"));
        assert!(recovery.rewritten_source.contains("function d("));
    }

    #[test]
    fn global_object_proxy_use_keeps_modern_scaffolding() {
        let source: &str = "function p(){const a=['zero'];p=function(){return a;};return p();}const alias=d;function d(i,_){const v=p();return v[i];}function w(i){return alias(i);}console.log(d(0),globalThis.w(index));";
        let recovery: ModernRecovery = recover_modern(source).expect("shape").expect("recovery");
        assert_eq!(recovery.call_sites_inlined, 1);
        assert!(recovery.rewritten_source.contains("function p("));
        assert!(recovery.rewritten_source.contains("function d("));
        assert!(recovery.rewritten_source.contains("function w("));
        assert!(recovery.rewritten_source.contains("globalThis.w(index)"));
    }
}
