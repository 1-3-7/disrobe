mod detect;
mod inline;
mod modern;
mod rotate;
mod sandbox;

use std::collections::BTreeSet;
use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, NodeId, Semantic, SemanticBuilder, SymbolId, SymbolTable};
use oxc_span::SourceType;
use serde::Serialize;

use crate::error::Result;

pub(crate) use sandbox::ProbeRefusal;

const MAX_TEMPLATE_SCAN_DEPTH: usize = 256;

pub(super) fn resolved_reference_starts(
    source: &str,
    names: &[&str],
    declaration_ranges: &[Range<usize>],
) -> Option<BTreeSet<usize>> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("string-array.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return None;
    }
    let semantic_return: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if !semantic_return.errors.is_empty() {
        return None;
    }
    let semantic: Semantic<'_> = semantic_return.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let nodes: &AstNodes<'_> = semantic.nodes();
    let required: BTreeSet<&str> = names.iter().copied().collect();
    let mut found: BTreeSet<&str> = BTreeSet::new();
    let mut targets: Vec<SymbolId> = Vec::new();
    for symbol_id in symbols.symbol_ids() {
        let name: &str = symbols.get_name(symbol_id);
        if !required.contains(name) {
            continue;
        }
        let span: oxc_span::Span = symbols.get_span(symbol_id);
        let start: usize = span.start as usize;
        let end: usize = span.end as usize;
        if declaration_ranges
            .iter()
            .any(|range: &Range<usize>| range.start <= start && end <= range.end)
        {
            found.insert(name);
            targets.push(symbol_id);
        }
    }
    if found != required {
        return None;
    }
    let mut starts: BTreeSet<usize> = BTreeSet::new();
    for symbol_id in targets {
        for &reference_id in symbols.get_resolved_reference_ids(symbol_id) {
            let node_id: NodeId = symbols.get_reference(reference_id).node_id();
            if let AstKind::IdentifierReference(identifier) = nodes.kind(node_id) {
                starts.insert(identifier.span.start as usize);
            }
        }
    }
    Some(starts)
}

pub(super) fn executable_code_exclusions(
    source: &str,
) -> core::result::Result<Vec<Range<usize>>, ProbeRefusal> {
    let mut exclusions: Vec<Range<usize>> = Vec::new();
    append_code_exclusions(source, 0, 0, 0, false, &mut exclusions)?;
    Ok(exclusions)
}

fn append_code_exclusions(
    source: &str,
    offset: usize,
    depth: usize,
    mut cursor: usize,
    stop_at_closing_brace: bool,
    exclusions: &mut Vec<Range<usize>>,
) -> core::result::Result<usize, ProbeRefusal> {
    if depth > MAX_TEMPLATE_SCAN_DEPTH {
        return Err(ProbeRefusal::UnsafeNesting);
    }
    let bytes: &[u8] = source.as_bytes();
    let mut brace_depth: usize = 0;
    let mut previous_significant: u8 = b';';
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\'' | b'"' => {
                let end: usize = crate::scan_utils::skip_string(bytes, cursor, bytes[cursor])
                    .unwrap_or(bytes.len());
                exclusions.push(offset + cursor..offset + end);
                previous_significant = bytes[cursor];
                cursor = end;
                continue;
            }
            b'`' => {
                cursor = append_template_exclusions(source, offset, depth, cursor, exclusions)?;
                previous_significant = b'`';
                continue;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'/') => {
                let start: usize = cursor;
                cursor += 2;
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    cursor += 1;
                }
                exclusions.push(offset + start..offset + cursor);
                continue;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                let start: usize = cursor;
                cursor += 2;
                while cursor + 1 < bytes.len()
                    && !(bytes[cursor] == b'*' && bytes[cursor + 1] == b'/')
                {
                    cursor += 1;
                }
                cursor = cursor.saturating_add(2).min(bytes.len());
                exclusions.push(offset + start..offset + cursor);
                continue;
            }
            b'/' if crate::scan_utils::regex_can_follow(previous_significant) => {
                let end: usize = crate::scan_utils::skip_regex_literal(bytes, cursor);
                exclusions.push(offset + cursor..offset + end);
                previous_significant = b'/';
                cursor = end;
                continue;
            }
            b'{' => brace_depth += 1,
            b'}' if stop_at_closing_brace && brace_depth == 0 => return Ok(cursor),
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        if !matches!(bytes[cursor], b' ' | b'\t' | b'\r' | b'\n') {
            previous_significant = bytes[cursor];
        }
        cursor += 1;
    }
    Ok(cursor)
}

fn append_template_exclusions(
    source: &str,
    offset: usize,
    depth: usize,
    start: usize,
    exclusions: &mut Vec<Range<usize>>,
) -> core::result::Result<usize, ProbeRefusal> {
    let bytes: &[u8] = source.as_bytes();
    let mut raw_start: usize = start;
    let mut cursor: usize = start + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = cursor.saturating_add(2).min(bytes.len());
            continue;
        }
        if bytes[cursor] == b'`' {
            exclusions.push(offset + raw_start..offset + cursor + 1);
            return Ok(cursor + 1);
        }
        if bytes[cursor] != b'$' || bytes.get(cursor + 1) != Some(&b'{') {
            cursor += 1;
            continue;
        }
        let expression_start: usize = cursor + 2;
        exclusions.push(offset + raw_start..offset + expression_start);
        let expression_end: usize = append_code_exclusions(
            source,
            offset,
            depth + 1,
            expression_start,
            true,
            exclusions,
        )?;
        if expression_end == bytes.len() {
            exclusions.push(offset + expression_end..offset + bytes.len());
            return Ok(bytes.len());
        }
        raw_start = expression_end;
        cursor = expression_end + 1;
    }
    exclusions.push(offset + raw_start..offset + bytes.len());
    Ok(bytes.len())
}

#[derive(Debug, Clone, Serialize)]
pub struct StringArrayRecovery {
    pub array_id: String,
    pub original_strings: Vec<String>,
    pub rotated_strings: Vec<String>,
    pub rotation_count: u32,
    pub rotator_removed: bool,
    pub decoder_name: Option<String>,
    pub call_sites_total: usize,
    pub call_sites_inlined: usize,
    pub rewritten_source: String,
}

#[allow(clippy::unnecessary_wraps)]
pub fn recover(source: &str) -> Result<Option<StringArrayRecovery>> {
    crate::debug::dbg_section("string-array recover");
    if let Some(modern) = modern::recover_modern(source)
        .map_err(|reason: ProbeRefusal| crate::error::Error::StringArrayProbe { reason })?
    {
        crate::debug::dbg_kv("shape", || "modern-self-reassigning-provider".to_owned());
        crate::debug::dbg_kv("provider", || modern.provider_name.clone());
        crate::debug::dbg_kv("rotation-count", || modern.rotation_count.to_string());
        crate::debug::dbg_kv("call-sites", || {
            format!(
                "inlined={}/{}",
                modern.call_sites_inlined, modern.call_sites_total
            )
        });
        return Ok(Some(StringArrayRecovery {
            array_id: modern.provider_name,
            original_strings: Vec::new(),
            rotated_strings: Vec::new(),
            rotation_count: modern.rotation_count,
            rotator_removed: modern.scaffolding_removed,
            decoder_name: Some(modern.decoder_name),
            call_sites_total: modern.call_sites_total,
            call_sites_inlined: modern.call_sites_inlined,
            rewritten_source: modern.rewritten_source,
        }));
    }
    let Some(found): Option<detect::StringArrayFound> = detect::find_string_array(source) else {
        crate::debug::dbg_line(|| "no static string array located".to_owned());
        return Ok(None);
    };
    crate::debug::dbg_kv("array-id", || found.array_id.clone());
    crate::debug::dbg_kv("literals", || found.literals.len().to_string());
    let Some(rotator): Option<detect::RotatorFound> = detect::find_rotator(source, &found.array_id)
    else {
        crate::debug::dbg_kv("rotator", || "none (decode without rotation)".to_owned());
        let inline_result: inline::InlineResult =
            inline::inline_decoder_calls(source, &found.array_id);
        if let Some(refusal) = inline_result.probe_refusal {
            return Err(crate::error::Error::StringArrayProbe { reason: refusal });
        }
        crate::debug::dbg_kv("call-sites", || {
            format!(
                "inlined={}/{}",
                inline_result.call_sites_inlined, inline_result.call_sites_total
            )
        });
        return Ok(Some(StringArrayRecovery {
            array_id: found.array_id,
            original_strings: found.literals.clone(),
            rotated_strings: found.literals,
            rotation_count: 0,
            rotator_removed: false,
            decoder_name: inline_result.decoder_name,
            call_sites_total: inline_result.call_sites_total,
            call_sites_inlined: inline_result.call_sites_inlined,
            rewritten_source: inline_result.rewritten_source,
        }));
    };
    crate::debug::dbg_kv("rotator", || {
        format!(
            "pivot-index={} pivot-value={}",
            rotator.pivot_index, rotator.pivot_value
        )
    });
    let rotated: (Vec<String>, u32) =
        rotate::simulate(&found.literals, rotator.pivot_index, rotator.pivot_value);
    crate::debug::dbg_kv("rotation-count", || rotated.1.to_string());
    let mid_source: String = detect::rebuild_source(source, &found, &rotator, &rotated);
    let inline_result: inline::InlineResult =
        inline::inline_decoder_calls(&mid_source, &found.array_id);
    if let Some(refusal) = inline_result.probe_refusal {
        return Err(crate::error::Error::StringArrayProbe { reason: refusal });
    }
    crate::debug::dbg_kv("call-sites", || {
        format!(
            "inlined={}/{}",
            inline_result.call_sites_inlined, inline_result.call_sites_total
        )
    });
    Ok(Some(StringArrayRecovery {
        array_id: found.array_id,
        original_strings: found.literals,
        rotated_strings: rotated.0,
        rotation_count: rotated.1,
        rotator_removed: true,
        decoder_name: inline_result.decoder_name,
        call_sites_total: inline_result.call_sites_total,
        call_sites_inlined: inline_result.call_sites_inlined,
        rewritten_source: inline_result.rewritten_source,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn public_recovery_preserves_typed_inline_refusal() {
        let source: &str = "var _arr=['x'];var _decode=function(i){return _arr[i]+Math.random();};console.log(_decode(0));";
        assert!(matches!(
            recover(source).expect_err("unstable inline decoder"),
            crate::error::Error::StringArrayProbe {
                reason: ProbeRefusal::EnvironmentDisagreement
            }
        ));
    }

    #[test]
    fn public_recovery_preserves_typed_modern_refusal() {
        let source: &str = "function p(){const a=['x'];p=function(){return a;};return p();}function d(i,_){return p()[i]+Math.random();}console.log(d(0));";
        assert!(matches!(
            recover(source).expect_err("unstable modern decoder"),
            crate::error::Error::StringArrayProbe {
                reason: ProbeRefusal::EnvironmentDisagreement
            }
        ));
    }

    #[test]
    fn public_recovery_rejects_more_than_maximum_call_sites() {
        let mut source: String = String::from(
            "function p(){const a=['x'];p=function(){return a;};return p();}function d(i,_){return p()[i];}",
        );
        for _ in 0..=65_536_usize {
            source.push_str("d(0);");
        }
        assert!(matches!(
            recover(&source).expect_err("call count must be bounded"),
            crate::error::Error::StringArrayProbe {
                reason: ProbeRefusal::BoundExceeded
            }
        ));
    }

    #[test]
    fn public_recovery_rejects_oversized_decoded_value() {
        let source: &str = "var _arr=['x'];var _decode=function(i){return _arr[i].repeat(65537);};console.log(_decode(0));";
        assert!(matches!(
            recover(source).expect_err("decoded value must be bounded"),
            crate::error::Error::StringArrayProbe {
                reason: ProbeRefusal::BoundExceeded
            }
        ));
    }

    #[test]
    fn executable_code_inventory_rejects_excessive_template_nesting() {
        let mut source: String = String::new();
        for _ in 0..=MAX_TEMPLATE_SCAN_DEPTH {
            source.push_str("`${");
        }
        source.push('0');
        for _ in 0..=MAX_TEMPLATE_SCAN_DEPTH {
            source.push_str("}`");
        }
        assert_eq!(
            executable_code_exclusions(&source),
            Err(ProbeRefusal::UnsafeNesting)
        );
    }
}
